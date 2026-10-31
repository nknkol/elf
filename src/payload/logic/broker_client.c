/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolation mode, payload side: host path syscalls become broker requests
 * (broker_proto.h). Every thread has its own channel to the broker, made on
 * first use and handed over through the inherited control socket; a forked
 * child notices the channel is its parent's and makes its own. */
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include "broker_proto.h"
#include "config.h"
#include "host_syscall.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#define O_CLOEXEC_ 02000000
#define CHANNEL_FD_BASE 900
#define CHANNELS 64
#define BUFFER_SIZE (2 * (BROKER_MESSAGE_MAX + 4096))

struct channel {
    long tid, pid;
    int fd;
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
        /* Another process's entry (fork copied it): its FD is a copy of a
         * channel this process must not use. */
        if (c->pid && c->pid != pid && c->fd > 0) {
            raw_syscall(__NR_close, c->fd, 0, 0, 0, 0, 0);
            c->tid = c->pid = 0;
            c->fd = 0;
        }
        if (!c->tid && !free_slot)
            free_slot = c;
    }
    if (free_slot) {
        free_slot->tid = tid;
        free_slot->pid = pid;
        free_slot->fd = -1;
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
    int directory = AT_FDCWD;
    int cloexec = nr == __NR_chdir || (nr == __NR_openat && (a[2] & O_CLOEXEC_));
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
    long a[6] = {a0, a1, a2, a3, a4, a5};
    return broker_call(spec, nr, a);
}
