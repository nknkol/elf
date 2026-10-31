/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolation mode, payload side: host path syscalls become broker requests
 * (broker_proto.h). Every thread has its own channel to the broker, made on
 * first use and handed over through the inherited control socket. A forked
 * child drops its copies of its parent's channels (broker_clone_finish); a
 * vfork child shares the table and takes a slot of its own. */
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include "broker_proto.h"
#include "config.h"
#include "host_syscall.h"
#include "platform.h"
#ifdef GUARDED
#include "fd_runtime.h"
#endif

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#define O_CLOEXEC_ 02000000
#define CHANNEL_FD_BASE 900
#define CHANNELS 64
#define BUFFER_SIZE (2 * (BROKER_MESSAGE_MAX + 4096) + 2 * 4096)
#define REPORT_OFFSET (2 * (BROKER_MESSAGE_MAX + 4096)) /* strict symlink report */

struct channel {
    long tid, pid;
    int fd;
    int strict; /* BROKER_STRICT on this thread's requests */
    int reported; /* the last strict refusal named a symlink (REPORT_OFFSET) */
    unsigned char *buffer; /* request then answer; kept across forks */
};
static struct channel channels[CHANNELS];
static int channels_lock;

static void lock(void)
{
    while (__atomic_exchange_n(&channels_lock, 1, __ATOMIC_ACQUIRE))
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
}
static void unlock(void) { __atomic_store_n(&channels_lock, 0, __ATOMIC_RELEASE); }

static long send_fds(int socket, const void *data, size_t length, const int *fds, unsigned count)
{
    char control[CMSG_SPACE(sizeof(int) * BROKER_FDS_MAX)];
    struct iovec io = {(void *)data, length};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1};
    if (count) {
        memset(control, 0, sizeof(control));
        message.msg_control = control;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * count);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * count);
        memcpy(CMSG_DATA(header), fds, sizeof(int) * count);
    }
    return raw_syscall(__NR_sendmsg, socket, (long)&message, MSG_NOSIGNAL, 0, 0, 0);
}

/* A new channel: one end stays here (high, close-on-exec), the other goes
 * to the broker. */
static int open_channel(void)
{
    int pair[2];
    long rc = raw_syscall(__NR_socketpair, AF_UNIX, SOCK_SEQPACKET | O_CLOEXEC_, 0, (long)pair, 0, 0);
    if (rc < 0)
        return (int)rc;
    long high = raw_syscall(__NR_fcntl, pair[0], 1030 /* F_DUPFD_CLOEXEC */, CHANNEL_FD_BASE, 0, 0, 0);
    raw_syscall(__NR_close, pair[0], 0, 0, 0, 0, 0);
    char hello = 'c';
    rc = high < 0 ? high : send_fds(g_payload_config.isolate_fd, &hello, 1, &pair[1], 1);
    raw_syscall(__NR_close, pair[1], 0, 0, 0, 0, 0);
    if (rc < 0) {
        if (high >= 0)
            raw_syscall(__NR_close, high, 0, 0, 0, 0, 0);
        return (int)rc;
    }
    return (int)high;
}

static void release_slot(struct channel *c)
{
    c->tid = c->pid = 0;
    c->fd = 0;
}

/* Under the lock, every slot taken: the slots of threads that have exited
 * (their FDs are in this process's table and close here) and of processes
 * that shared this memory and are gone (their FDs were in their own table). */
static struct channel *reclaim(long pid)
{
    struct channel *found = 0;
    for (int i = 0; i < CHANNELS; i++) {
        struct channel *c = &channels[i];
        if (c->fd <= 0) /* being opened */
            continue;
        if (c->pid == pid) {
            if (raw_syscall(__NR_tgkill, pid, c->tid, 0, 0, 0, 0) != -ESRCH)
                continue;
            raw_syscall(__NR_close, c->fd, 0, 0, 0, 0, 0);
        } else if (raw_syscall(__NR_kill, c->pid, 0, 0, 0, 0, 0) != -ESRCH)
            continue;
        release_slot(c);
        if (!found)
            found = c;
    }
    return found;
}

static struct channel *channel(void)
{
    long tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    long pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    struct channel *free_slot = 0;
    lock();
    for (int i = 0; i < CHANNELS; i++) {
        struct channel *c = &channels[i];
        if (c->tid == tid && c->pid == pid) {
            unlock();
            return c;
        }
        if (!c->tid && !free_slot)
            free_slot = c;
    }
    if (!free_slot)
        free_slot = reclaim(pid);
    if (free_slot) {
        free_slot->tid = tid;
        free_slot->pid = pid;
        free_slot->fd = -1;
        free_slot->strict = 0;
    }
    unlock();
    if (!free_slot)
        return 0;
    if (!free_slot->buffer) {
        long mem = raw_syscall(__NR_mmap, 0, BUFFER_SIZE, 3, 0x22, -1, 0);
        if (mem < 0 && mem > -4096) {
            free_slot->tid = free_slot->pid = 0;
            return 0;
        }
        free_slot->buffer = (unsigned char *)mem;
    }
    free_slot->fd = open_channel();
    if (free_slot->fd < 0) {
        free_slot->tid = free_slot->pid = 0;
        return 0;
    }
    return free_slot;
}

/* "/proc/self/fd/N" (or thread-self): the FD number, else -1. */
static int magic_fd(const char *path)
{
    static const char *const prefixes[] = {"/proc/self/fd/", "/proc/thread-self/fd/"};
    for (int k = 0; k < 2; k++) {
        size_t n = strlen(prefixes[k]);
        if (strncmp(path, prefixes[k], n))
            continue;
        long fd = 0;
        const char *p = path + n;
        if (!*p)
            return -1;
        for (; *p; p++) {
            if (*p < '0' || *p > '9' || fd > 1 << 20)
                return -1;
            fd = fd * 10 + (*p - '0');
        }
        return (int)fd;
    }
    return -1;
}

static long broker_call(const struct broker_spec *spec, long nr, const long a[6])
{
    struct channel *c = channel();
    if (!c)
        return -EACCES;
    struct broker_request *request = (struct broker_request *)c->buffer;
    unsigned char *data = c->buffer + sizeof(*request);
    size_t used = 0;
    int fds[BROKER_FDS_MAX];
    memset(request, 0, sizeof(*request));
    request->nr = (int32_t)nr;
    if (c->strict)
        request->flags |= BROKER_STRICT;
    int directory = AT_FDCWD;
    int cloexec = nr == __NR_chdir || (nr == __NR_openat && (a[2] & O_CLOEXEC_)) ||
                  (nr == __NR_socket && (a[1] & O_CLOEXEC_));
    for (int i = 0; i < 6; i++) {
        const struct broker_arg *arg = &spec->arg[i];
        size_t length = arg->len_arg >= 0 ? (size_t)a[arg->len_arg] : arg->len_fixed;
        request->args[i] = a[i];
        switch (arg->kind) {
        case BK_DIRFD:
            directory = (int)a[i];
            break;
        case BK_FD:
            if (request->fds == BROKER_FDS_MAX)
                return -EINVAL;
            fds[request->fds++] = (int)a[i];
            break;
        case BK_PATH: {
            const char *path = (const char *)a[i];
            int magic = path ? magic_fd(path) : -1;
            if (magic >= 0) {
                directory = magic;
                path = "";
                request->flags |= BROKER_MAGIC(i);
            }
            if (directory != AT_FDCWD) {
                if (request->fds == BROKER_FDS_MAX)
                    return -EINVAL;
                fds[request->fds++] = directory;
            }
            if (!path)
                break;
            size_t n = strlen(path) + 1;
            /* Relative to the cwd: the broker gets an absolute host path. */
            if (path[0] && path[0] != '/' && directory == AT_FDCWD) {
                long cwd = raw_syscall(__NR_getcwd, (long)data + used, 4096, 0, 0, 0, 0);
                if (cwd < 0)
                    return cwd;
                size_t base = strlen((char *)data + used);
                if (base + 1 + n > 8192 || used + base + 1 + n > BROKER_DATA_MAX)
                    return -ENAMETOOLONG;
                data[used + base] = '/';
                memcpy(data + used + base + 1, path, n);
                request->len[i] = (uint32_t)(base + 1 + n);
            } else {
                if (n > 8192 || used + n > BROKER_DATA_MAX)
                    return -ENAMETOOLONG;
                memcpy(data + used, path, n);
                request->len[i] = (uint32_t)n;
            }
            used += request->len[i];
            directory = AT_FDCWD;
            break;
        }
        case BK_STR:
            if (!a[i])
                return -EFAULT;
            length = strlen((const char *)a[i]) + 1;
            /* fall through */
        case BK_IN:
            if (!a[i])
                break;
            if (length > BROKER_DATA_MAX - used)
                return -E2BIG;
            memcpy(data + used, (const void *)a[i], length);
            request->len[i] = (uint32_t)length;
            used += length;
            break;
        case BK_OUT:
            if (length > BROKER_DATA_MAX)
                length = BROKER_DATA_MAX;
            request->len[i] = (uint32_t)length;
            break;
        }
    }
    long rc = send_fds(c->fd, c->buffer, sizeof(*request) + used, fds, request->fds);
    if (rc < 0)
        return rc == -EPIPE || rc == -ECONNRESET ? -EACCES : rc;

    unsigned char *reply = c->buffer + BROKER_MESSAGE_MAX + 4096;
    char control[CMSG_SPACE(sizeof(int))];
    struct iovec io = {reply, BROKER_MESSAGE_MAX};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1,
                             .msg_control = control, .msg_controllen = sizeof(control)};
    do
        rc = raw_syscall(__NR_recvmsg, c->fd, (long)&message, cloexec ? MSG_CMSG_CLOEXEC : 0, 0, 0, 0);
    while (rc == -EINTR);
    if (rc < (long)sizeof(struct broker_answer))
        return -EACCES; /* The broker is gone: no file access (fail closed). */
    struct broker_answer *answer = (struct broker_answer *)reply;
    int received = -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (header && header->cmsg_type == SCM_RIGHTS)
        memcpy(&received, CMSG_DATA(header), sizeof(int));
    unsigned char *out = reply + sizeof(*answer);
    for (int i = 0; i < 6; i++) {
        if (spec->arg[i].kind != BK_OUT || !answer->len[i])
            continue;
        if (answer->len[i] > request->len[i] || out + answer->len[i] > reply + rc)
            return -EIO;
        memcpy((void *)a[i], out, answer->len[i]);
        out += answer->len[i];
    }
    c->reported = 0;
    if (answer->result == -ELOOP && answer->link[0] && answer->link[1] &&
        answer->link[0] <= 4096 && answer->link[1] <= 4096 &&
        out + answer->link[0] + answer->link[1] <= reply + rc &&
        !out[answer->link[0] - 1] && !out[answer->link[0] + answer->link[1] - 1]) {
        memcpy(c->buffer + REPORT_OFFSET, out, answer->link[0]);
        memcpy(c->buffer + REPORT_OFFSET + 4096, out + answer->link[0], answer->link[1]);
        c->reported = 1;
    }
    if (received >= 0) {
        if (nr == __NR_chdir) {
            long changed = raw_syscall(__NR_fchdir, received, 0, 0, 0, 0, 0);
            raw_syscall(__NR_close, received, 0, 0, 0, 0, 0);
            return changed;
        }
        return received;
    }
    return answer->result;
}

long host_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5)
{
    const struct broker_spec *spec;
    if (!g_payload_config.isolate || !(spec = broker_spec(nr)))
        return raw_syscall(nr, a0, a1, a2, a3, a4, a5);
    /* fstat spelled as fstatat (glibc): the FD's own metadata, no path. */
    if (nr == __NR_newfstatat && (int)a0 != AT_FDCWD && a1 && !*(const char *)a1 &&
        (a3 & 0x1000 /* AT_EMPTY_PATH */))
        return raw_syscall(__NR_fstat, a0, a2, 0, 0, 0, 0);
    long a[6] = {a0, a1, a2, a3, a4, a5};
    return broker_call(spec, nr, a);
}

/* The control socket, the loader binary and the channels stay open and
 * keep their flags whatever the guest closes (closefrom loops, dup2 over
 * them): without them no file can be reached. */
static int reserved(long fd)
{
    if (fd < 0)
        return 0;
    if (fd == g_payload_config.isolate_fd || fd == g_payload_config.loader_fd)
        return 1;
    for (int i = 0; i < CHANNELS; i++)
        if (__atomic_load_n(&channels[i].fd, __ATOMIC_RELAXED) == fd && fd > 0)
            return 1;
    return 0;
}

#define CLOSE_RANGE_UNSHARE_ 2u
#define CLOSE_RANGE_CLOEXEC_ 4u

static void close_unreserved(unsigned long fd, unsigned flags)
{
    if (reserved((long)fd))
        return;
    long nr = flags & CLOSE_RANGE_CLOEXEC_ ? __NR_fcntl : __NR_close;
    long a[6] = {(long)fd, 2 /* F_SETFD */, 1 /* FD_CLOEXEC */, 0, 0, 0};
#ifdef GUARDED
    fd_runtime_dispatch(nr, a); /* The FD runtime keeps its records. */
#else
    raw_syscall(nr, a[0], a[1], a[2], 0, 0, 0);
#endif
}

#ifndef GUARDED
/* The kernel call on the stretches between the reserved FDs. */
static long close_range_between(unsigned first, unsigned last, unsigned flags)
{
    int held[CHANNELS + 2], count = 0;
    held[count++] = g_payload_config.isolate_fd;
    held[count++] = g_payload_config.loader_fd;
    for (int i = 0; i < CHANNELS; i++) {
        int fd = __atomic_load_n(&channels[i].fd, __ATOMIC_RELAXED);
        if (fd > 0)
            held[count++] = fd;
    }
    for (int i = 1; i < count; i++)
        for (int j = i; j > 0 && held[j - 1] > held[j]; j--) {
            int t = held[j];
            held[j] = held[j - 1];
            held[j - 1] = t;
        }
    unsigned long from = first;
    for (int i = 0; i < count && from <= last; i++) {
        if (held[i] < 0 || (unsigned long)held[i] < from)
            continue;
        if ((unsigned long)held[i] > from) {
            unsigned long to = (unsigned long)held[i] - 1 < last ? (unsigned long)held[i] - 1 : last;
            long rc = raw_syscall(__NR_close_range, (long)from, (long)to, flags, 0, 0, 0);
            if (rc < 0)
                return rc;
        }
        from = (unsigned long)held[i] + 1;
    }
    return from <= last ? raw_syscall(__NR_close_range, (long)from, (long)last, flags, 0, 0, 0) : 0;
}
#endif

/* Without the kernel call (HarmonyOS refuses it): the open FDs from a
 * /proc/self/fd listing, which the broker opens for this process; failing
 * that, every number below the FD limit. */
static long close_range_listed(unsigned first, unsigned last, unsigned flags)
{
    long dir = host_syscall(__NR_openat, AT_FDCWD, (long)"/proc/self/fd",
                            00 | 040000 /* O_DIRECTORY */ | O_CLOEXEC_, 0, 0, 0);
    if (dir < 0) {
        unsigned long limit[2];
        if (raw_syscall(__NR_prlimit64, 0, 7 /* RLIMIT_NOFILE */, 0, (long)limit, 0, 0) < 0)
            limit[0] = 1024;
        unsigned long end = limit[0] > 1ul << 20 ? 1ul << 20 : limit[0];
        for (unsigned long fd = first; fd <= last && fd < end; fd++)
            close_unreserved(fd, flags);
        return 0;
    }
    char buffer[1024];
    long n;
    while ((n = raw_syscall(__NR_getdents64, dir, (long)buffer, sizeof(buffer), 0, 0, 0)) > 0)
        for (long at = 0; at < n;) {
            unsigned short length; /* ino, offset, reclen, type, name */
            memcpy(&length, buffer + at + 16, sizeof(length));
            const char *name = buffer + at + 19;
            at += length;
            if (*name < '0' || *name > '9')
                continue;
            unsigned long fd = 0;
            for (; *name >= '0' && *name <= '9'; name++)
                fd = fd * 10 + (unsigned long)(*name - '0');
            if (fd >= first && fd <= last && fd != (unsigned long)dir)
                close_unreserved(fd, flags);
        }
    raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0);
    return n < 0 ? n : 0;
}

/* close_range that leaves the reserved FDs alone and still succeeds:
 * glibc's closefrom fallback (posix_spawn, Python's subprocess) rereads
 * /proc/self/fd from the start after every pass that closed something, so
 * an FD that stays open while close reports success would loop it forever. */
static long close_range_unreserved(unsigned first, unsigned last, unsigned flags)
{
    if (first > last || (flags & ~(CLOSE_RANGE_UNSHARE_ | CLOSE_RANGE_CLOEXEC_)))
        return -EINVAL;
#ifndef GUARDED
    if (!platform_is_harmonyos()) {
        long rc = close_range_between(first, last, flags);
        if (rc != -ENOSYS)
            return rc;
    }
#endif
    /* Unsharing the table needs the kernel call. */
    if (flags & CLOSE_RANGE_UNSHARE_)
        return -ENOSYS;
    return close_range_listed(first, last, flags);
}

int broker_fd_guard(long nr, const long a[6], long *result)
{
    if (!g_payload_config.isolate)
        return 0;
    switch (nr) {
    case __NR_close:
        if (!reserved((int)a[0]))
            return 0;
        *result = 0;
        return 1;
    case __NR_dup3:
        if (!reserved((int)a[1]))
            return 0;
        *result = -EBUSY;
        return 1;
    case __NR_fcntl:
        if (a[1] != 2 /* F_SETFD */ || !reserved((int)a[0]))
            return 0;
        *result = 0;
        return 1;
    case __NR_ioctl:
        if ((unsigned)a[1] != 0x5451 /* FIOCLEX */ || !reserved((int)a[0]))
            return 0;
        *result = 0;
        return 1;
    case __NR_close_range:
        *result = close_range_unreserved((unsigned)a[0], (unsigned)a[1], (unsigned)a[2]);
        return 1;
    default:
        return 0;
    }
}

void broker_clone_finish(unsigned long flags, long result)
{
    if (!g_payload_config.isolate || result < 0)
        return;
    if (!result && !(flags & 0x100 /* CLONE_VM */)) {
        /* A private copy: the FDs are copies of the parent's channels, and
         * a lock another thread held is copied held. Buffers stay. */
        for (int i = 0; i < CHANNELS; i++) {
            if (channels[i].fd > 0)
                raw_syscall(__NR_close, channels[i].fd, 0, 0, 0, 0, 0);
            release_slot(&channels[i]);
        }
        unlock();
    } else if (result && (flags & 0x4000 /* CLONE_VFORK */)) {
        /* The child has exec'd or exited: its slot is free, its FD was in
         * its own table. */
        lock();
        for (int i = 0; i < CHANNELS; i++)
            if (channels[i].pid == result)
                release_slot(&channels[i]);
        unlock();
    }
}

/* A procfs listing of FDs (fd: links, fdinfo: files) without the payload's
 * own: glibc's closefrom fallback and FD-walking tools see only the guest's. */
long broker_hide_fds(int fd, void *buffer, long length)
{
    if (!g_payload_config.isolate)
        return length;
    unsigned long fs[16]; /* struct statfs; f_type first */
    if (raw_syscall(__NR_fstatfs, fd, (long)fs, 0, 0, 0, 0) || (unsigned)fs[0] != 0x9fa0 /* PROC_SUPER_MAGIC */)
        return length;
    unsigned char *bytes = buffer;
    long kept = 0;
    for (long at = 0; at < length;) {
        unsigned short size; /* ino, offset, reclen, type, name */
        memcpy(&size, bytes + at + 16, sizeof(size));
        if (size < 20 || at + size > length)
            return length;
        unsigned char type = bytes[at + 18];
        const char *name = (const char *)bytes + at + 19;
        long number = *name ? 0 : -1;
        for (const char *p = name; *p && number >= 0; p++)
            number = *p >= '0' && *p <= '9' && number < 1 << 20 ? number * 10 + (*p - '0') : -1;
        if (!((type == 10 /* DT_LNK */ || type == 8 /* DT_REG */) && reserved(number))) {
            memmove(bytes + kept, bytes + at, size);
            kept += size;
        }
        at += size;
    }
    return kept;
}

void broker_strict(int on)
{
    struct channel *c = g_payload_config.isolate ? channel() : 0;
    if (c)
        c->strict = on;
}

int broker_link_report(char *path, char *target)
{
    struct channel *c = g_payload_config.isolate ? channel() : 0;
    if (!c || !c->reported)
        return 0;
    c->reported = 0;
    strcpy(path, (char *)c->buffer + REPORT_OFFSET);
    strcpy(target, (char *)c->buffer + REPORT_OFFSET + 4096);
    return 1;
}

int broker_route(long nr, long a[6], long *result)
{
    if (!g_payload_config.isolate)
        return 0;
    switch (nr) {
    case __NR_socket:
        if (a[0] != AF_UNIX)
            return 0;
        break;
    case __NR_socketpair:
        /* A datagram may be sent to any name; a connected pair of sequenced
         * packets keeps the message boundaries. */
        if (a[0] == AF_UNIX && (a[1] & 0xf) == SOCK_DGRAM)
            a[1] = (a[1] & ~0xfl) | SOCK_SEQPACKET;
        return 0;
    case __NR_prlimit64:
        /* The filter allows only pid 0 (the caller). */
        if (a[0] && a[0] == raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0))
            a[0] = 0;
        return 0;
    case __NR_fsetxattr:
    case __NR_fremovexattr:
        break;
    default:
        return 0;
    }
    *result = broker_call(broker_spec(nr), nr, a);
    return 1;
}
