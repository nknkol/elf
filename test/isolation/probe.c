/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolation acceptance probe (docs/ISOLATION_TESTING.md). Models the guest
 * of the capability assumptions: each operation runs either through the
 * normal (hooked) path, "h", or as a kernel call issued from the payload's
 * own `svc; ret`, "d", which skips every payload check. Prints one line per
 * result: "<label> <value>" where value is the return value or -errno.
 *
 *   probe h|d open PATH FLAGS        open (octal flags); prints data= on success
 *   probe h|d stat|lstat|readlink|list|chdir|statfs|getxattr PATH
 *   probe h|d mkdir|unlink|rmdir|chmod|chown|utime|truncate|setxattr PATH
 *   probe h|d rename|link|symlink A B
 *   probe h|d exec PATH              execve (h) or execveat by path (d)
 *   probe h   execfd PATH            open, then execveat(fd, "", AT_EMPTY_PATH)
 *   probe h   fdops PATH             open read-only, then FD metadata calls
 *   probe h|d bind|connect PATH      UNIX stream socket
 *   probe d   filter                 every refused call number from the payload's svc
 *   probe h   tamper HOSTPATH RWPATH ROPATH   rewrite the payload configuration
 *   probe h   forge HOST_OUT HOST_RO HOST_RW HOST_SOCK  raw broker requests
 *   probe h   killbroker PATH        kill the broker, then open PATH
 *   probe h   procs                  other processes' memory and FDs */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <asm/unistd.h>
#include "config.h"
#include "elf_abi.h"
#include "broker_proto.h"

static unsigned long gadget;
static int direct;

static long via(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    register unsigned long x16 __asm__("x16") = gadget;
    __asm__ volatile("blr x16" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5),
                     "r"(x16) : "memory", "cc", "x30");
    return x0;
}
/* Hooked: the probe's own svc, patched by the loader into the payload. */
static long hooked(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}
static long sc(long n, long a, long b, long c, long d, long e, long f)
{
    return direct ? via(n, a, b, c, d, e, f) : hooked(n, a, b, c, d, e, f);
}

static void report(const char *label, long v) { printf("%s %ld\n", label, v); fflush(stdout); }

static void find_gadget(void)
{
    for (unsigned *p = (unsigned *)PAYLOAD_FIXED_BASE; p < (unsigned *)(PAYLOAD_FIXED_BASE + 0x200000); p++)
        if (p[0] == 0xd4000001 && p[1] == 0xd65f03c0) {
            gadget = (unsigned long)p;
            return;
        }
    printf("gadget missing\n");
    exit(2);
}

static payload_config_t *payload_config(void)
{
    for (uint32_t *p = (uint32_t *)PAYLOAD_FIXED_BASE; p < (uint32_t *)(PAYLOAD_FIXED_BASE + 0x200000); p++)
        if (p[0] == CONFIG_MAGIC && p[2] == PAYLOAD_ABI_VERSION && p[1])
            return (payload_config_t *)((char *)(p - 1) + p[1]);
    return 0;
}

static void open_read(const char *label, const char *path, int flags)
{
    long fd = sc(__NR_openat, AT_FDCWD, (long)path, flags, 0644, 0, 0);
    report(label, fd < 0 ? fd : 0);
    if (fd >= 0) {
        char buf[65];
        long n = sc(__NR_read, fd, (long)buf, 64, 0, 0, 0);
        if (n > 0) {
            buf[n] = 0;
            for (long i = 0; i < n; i++)
                if (buf[i] == '\n') buf[i] = ' ';
            printf("data=%s\n", buf);
        }
        sc(__NR_close, fd, 0, 0, 0, 0, 0);
    }
}

static long path_op(const char *op, const char *p, const char *q)
{
    char buf[4096];
    struct timespec ts[2] = {{1, 0}, {1, 0}};
    if (!strcmp(op, "stat")) return sc(__NR_newfstatat, AT_FDCWD, (long)p, (long)buf, 0, 0, 0);
    if (!strcmp(op, "lstat")) return sc(__NR_newfstatat, AT_FDCWD, (long)p, (long)buf, AT_SYMLINK_NOFOLLOW, 0, 0);
    if (!strcmp(op, "statx")) return sc(__NR_statx, AT_FDCWD, (long)p, 0, 0xfff, (long)buf, 0);
    if (!strcmp(op, "readlink")) return sc(__NR_readlinkat, AT_FDCWD, (long)p, (long)buf, sizeof(buf), 0, 0);
    if (!strcmp(op, "access")) return sc(__NR_faccessat, AT_FDCWD, (long)p, 4, 0, 0, 0);
    if (!strcmp(op, "statfs")) return sc(__NR_statfs, (long)p, (long)buf, 0, 0, 0, 0);
    if (!strcmp(op, "chdir")) return sc(__NR_chdir, (long)p, 0, 0, 0, 0, 0);
    if (!strcmp(op, "getxattr")) return sc(__NR_getxattr, (long)p, (long)"user.x", (long)buf, 64, 0, 0);
    if (!strcmp(op, "listxattr")) return sc(__NR_listxattr, (long)p, (long)buf, 64, 0, 0, 0);
    if (!strcmp(op, "mkdir")) return sc(__NR_mkdirat, AT_FDCWD, (long)p, 0755, 0, 0, 0);
    if (!strcmp(op, "mknod")) return sc(__NR_mknodat, AT_FDCWD, (long)p, S_IFIFO | 0644, 0, 0, 0);
    if (!strcmp(op, "unlink")) return sc(__NR_unlinkat, AT_FDCWD, (long)p, 0, 0, 0, 0);
    if (!strcmp(op, "rmdir")) return sc(__NR_unlinkat, AT_FDCWD, (long)p, AT_REMOVEDIR, 0, 0, 0);
    if (!strcmp(op, "chmod")) return sc(__NR_fchmodat, AT_FDCWD, (long)p, 0777, 0, 0, 0);
    if (!strcmp(op, "chown")) return sc(__NR_fchownat, AT_FDCWD, (long)p, getuid(), getgid(), 0, 0);
    if (!strcmp(op, "utime")) return sc(__NR_utimensat, AT_FDCWD, (long)p, (long)ts, 0, 0, 0);
    if (!strcmp(op, "truncate")) return sc(__NR_truncate, (long)p, 0, 0, 0, 0, 0);
    if (!strcmp(op, "setxattr")) return sc(__NR_setxattr, (long)p, (long)"user.x", (long)"v", 1, 0, 0);
    if (!strcmp(op, "removexattr")) return sc(__NR_removexattr, (long)p, (long)"user.x", 0, 0, 0, 0);
    if (!strcmp(op, "inotify")) {
        int in = inotify_init1(0);
        return sc(__NR_inotify_add_watch, in, (long)p, 0xfff, 0, 0, 0);
    }
    if (!strcmp(op, "rename")) return sc(__NR_renameat, AT_FDCWD, (long)p, AT_FDCWD, (long)q, 0, 0);
    if (!strcmp(op, "link")) return sc(__NR_linkat, AT_FDCWD, (long)p, AT_FDCWD, (long)q, 0, 0);
    if (!strcmp(op, "symlink")) return sc(__NR_symlinkat, (long)p, AT_FDCWD, (long)q, 0, 0, 0);
    return -9999;
}

static void list(const char *path)
{
    long fd = sc(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_DIRECTORY, 0, 0, 0);
    report("list", fd < 0 ? fd : 0);
    if (fd < 0) return;
    char buf[4096];
    long n = sc(__NR_getdents64, fd, (long)buf, sizeof(buf), 0, 0, 0);
    printf("names=");
    for (long off = 0; off < n;) {
        unsigned short reclen = *(unsigned short *)(buf + off + 16);
        printf("%s,", buf + off + 19);
        off += reclen;
    }
    printf("\n");
}

static long unix_socket(const char *op, const char *path)
{
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strncpy(a.sun_path, path, sizeof(a.sun_path) - 1);
    long s = sc(__NR_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
    if (s < 0 && direct) s = socket(AF_UNIX, SOCK_STREAM, 0); /* the broker's, then name it directly */
    if (s < 0) return s;
    return sc(!strcmp(op, "bind") ? __NR_bind : __NR_connect, s, (long)&a, sizeof(a), 0, 0, 0);
}

static void fdops(const char *path)
{
    long fd = hooked(__NR_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    report("open", fd);
    if (fd < 0) return;
    char magic[64];
    snprintf(magic, sizeof(magic), "/proc/self/fd/%ld", fd);
    long re = hooked(__NR_openat, AT_FDCWD, (long)magic, O_RDWR, 0, 0, 0);
    report("reopen-rw", re < 0 ? re : 0);
    re = hooked(__NR_openat, AT_FDCWD, (long)magic, O_RDONLY, 0, 0, 0);
    report("reopen-ro", re < 0 ? re : 0);
    struct timespec ts[2] = {{1, 0}, {1, 0}};
    report("fchmod", hooked(__NR_fchmod, fd, 0777, 0, 0, 0, 0));
    report("fchown", hooked(__NR_fchown, fd, getuid(), getgid(), 0, 0, 0));
    report("futimens", hooked(__NR_utimensat, fd, 0, (long)ts, 0, 0, 0));
    report("fsetxattr", hooked(__NR_fsetxattr, fd, (long)"user.x", (long)"v", 1, 0, 0));
    report("ftruncate", hooked(__NR_ftruncate, fd, 0, 0, 0, 0, 0));
    report("write", hooked(__NR_write, fd, (long)"x", 1, 0, 0, 0));
    struct stat st;
    report("fstat", hooked(__NR_fstat, fd, (long)&st, 0, 0, 0, 0));
    char buf[256];
    report("statx-fd", hooked(__NR_statx, fd, (long)"", AT_EMPTY_PATH, 0xfff, (long)buf, 0));
    /* The same FD metadata changes straight from the payload's svc. */
    report("d-fchmod", via(__NR_fchmod, fd, 0777, 0, 0, 0, 0));
    report("d-futimens", via(__NR_utimensat, fd, 0, (long)ts, 0, 0, 0));
    report("d-fsetxattr", via(__NR_fsetxattr, fd, (long)"user.x", (long)"v", 1, 0, 0));
}

/* Every call of the guest filter table, from the payload's svc, in a child
 * (the host sandbox kills some calls with SIGSYS before ours answers). */
static void filter(void)
{
    static const int nrs[] = {56, 437, 264, 265, 79, 291, 48, 439, 78, 34, 33, 35, 36, 37, 38, 276,
        53, 452, 54, 88, 45, 43, 49, 51, 5, 6, 8, 9, 11, 12, 14, 15, 463, 464, 465, 466, 468, 469,
        27, 263, 89, 224, 225, 60, 221, 52, 55, 7, 16, 200, 203, 425, 426, 427, 270, 271, 440, 438,
        117, 272, 280, 241, 40, 39, 41, 428, 429, 430, 431, 432, 433, 442, 467};
    static char path[] = "/nonexistent-iso";
    for (unsigned i = 0; i < sizeof(nrs) / sizeof(nrs[0]); i++) {
        int pipefd[2];
        pipe(pipefd);
        pid_t pid = fork();
        if (!pid) {
            /* Harmless arguments: a path that does not exist, bad FDs. */
            long a0 = -1, a1 = (long)path;
            if (nrs[i] == 200 || nrs[i] == 203) a0 = socket(AF_INET, SOCK_STREAM, 0);
            if (nrs[i] == 117) a0 = 16 /* PTRACE_ATTACH */, a1 = getppid();
            long rc = via(nrs[i], a0, a1, 0, 0, 0, 0);
            write(pipefd[1], &rc, sizeof(rc));
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        long rc = -9999;
        close(pipefd[1]);
        if (read(pipefd[0], &rc, sizeof(rc)) != sizeof(rc))
            rc = WIFSIGNALED(status) ? -1000 - WTERMSIG(status) : -9999;
        close(pipefd[0]);
        printf("nr%d %ld\n", nrs[i], rc);
    }
    /* Conditional rules. */
    printf("execveat-path %ld\n", via(281, AT_FDCWD, (long)path, 0, 0, 0, 0));
    printf("execveat-empty %ld\n", via(281, -1, (long)"", 0, 0, AT_EMPTY_PATH, 0));
    printf("socket-unix %ld\n", via(__NR_socket, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0));
    printf("socket-inet %d\n", via(__NR_socket, AF_INET, SOCK_STREAM, 0, 0, 0, 0) >= 0);
    int sv[2];
    printf("socketpair-dgram %ld\n", via(__NR_socketpair, AF_UNIX, SOCK_DGRAM, 0, (long)sv, 0, 0));
    printf("socketpair-stream %ld\n", via(__NR_socketpair, AF_UNIX, SOCK_STREAM, 0, (long)sv, 0, 0));
    struct { unsigned long cur, max; } lim;
    printf("prlimit-self %ld\n", via(__NR_prlimit64, 0, 7, 0, (long)&lim, 0, 0));
    printf("prlimit-other %ld\n", via(__NR_prlimit64, getppid(), 7, 0, (long)&lim, 0, 0));
    printf("ioctl-setflags %ld\n", via(__NR_ioctl, 0, 0x40086602, (long)&lim, 0, 0, 0));
    printf("getpid-ok %d\n", via(__NR_getpid, 0, 0, 0, 0, 0, 0) == getpid());
    printf("nr-high-bits %ld\n", via(0x100000000l | 56, AT_FDCWD, (long)path, 0, 0, 0, 0));
    /* In a new thread and after exec the filter holds too: fork child above
     * covers fork; exec is covered by running this probe from a shell. */
}

/* Rewrite the payload configuration: everything writable, root at the
 * host root, then (separately) isolation off. */
static void tamper(const char *host_out, const char *rw, const char *ro)
{
    payload_config_t *cfg = payload_config();
    report("config-found", cfg != 0);
    if (!cfg) return;
    unsigned long page = (unsigned long)cfg & ~4095ul;
    report("mprotect", via(__NR_mprotect, page, (sizeof(*cfg) + 8191) & ~4095ul, 3, 0, 0, 0));
    for (int i = 0; cfg->mount_access_observe[i]; i++)
        cfg->mount_access_observe[i] = 'w';
    cfg->guard = 0;
    strcpy(cfg->root, "/");
    open_read("t-open-host", host_out, O_RDONLY);
    open_read("t-write-ro", ro, O_WRONLY | O_TRUNC);
    report("t-unlink-ro", hooked(__NR_unlinkat, AT_FDCWD, (long)ro, 0, 0, 0, 0));
    (void)rw;
    cfg->isolate = 0;
    open_read("t-noisolate-host", host_out, O_RDONLY);
    open_read("t-noisolate-ro", ro, O_WRONLY | O_TRUNC);
}

/* A channel of our own to the broker, and raw requests on it. */
static long request(int ch, struct broker_request *r, size_t size, int *fds, int nfds, char *out, size_t cap)
{
    char control[CMSG_SPACE(sizeof(int) * 4)];
    struct iovec io = {r, size};
    struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1};
    if (nfds) {
        memset(control, 0, sizeof(control));
        m.msg_control = control;
        m.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
        struct cmsghdr *h = CMSG_FIRSTHDR(&m);
        h->cmsg_level = SOL_SOCKET;
        h->cmsg_type = SCM_RIGHTS;
        h->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
        memcpy(CMSG_DATA(h), fds, sizeof(int) * nfds);
    }
    long sent = via(__NR_sendmsg, ch, (long)&m, MSG_NOSIGNAL, 0, 0, 0);
    if (sent < 0) return sent;
    char answer[sizeof(struct broker_answer) + 4096], rcontrol[CMSG_SPACE(sizeof(int))];
    struct iovec rio = {answer, sizeof(answer)};
    struct msghdr rm = {.msg_iov = &rio, .msg_iovlen = 1, .msg_control = rcontrol,
                        .msg_controllen = sizeof(rcontrol)};
    long n = via(__NR_recvmsg, ch, (long)&rm, 0, 0, 0, 0);
    if (n < (long)sizeof(struct broker_answer)) return n < 0 ? n : -7777;
    struct broker_answer *a = (struct broker_answer *)answer;
    struct cmsghdr *h = CMSG_FIRSTHDR(&rm);
    if (h && h->cmsg_type == SCM_RIGHTS) {
        int fd;
        memcpy(&fd, CMSG_DATA(h), sizeof(int));
        if (out) {
            long k = read(fd, out, cap - 1);
            out[k > 0 ? k : 0] = 0;
        }
        return 1000 + fd; /* an FD came back */
    }
    return a->result;
}

static size_t with_paths(struct broker_request *r, int nr, const char *p0, int i0, const char *p1, int i1)
{
    memset(r, 0, sizeof(*r));
    r->nr = nr;
    char *data = (char *)(r + 1);
    size_t used = 0;
    if (p0) { strcpy(data, p0); r->len[i0] = strlen(p0) + 1; used += r->len[i0]; }
    if (p1) { strcpy(data + used, p1); r->len[i1] = strlen(p1) + 1; used += r->len[i1]; }
    return sizeof(*r) + used;
}

static void forge(const char *out, const char *ro, const char *rw, const char *sock)
{
    payload_config_t *cfg = payload_config();
    if (!cfg || !cfg->isolate) { report("isolated", 0); return; }
    int pair[2];
    via(__NR_socketpair, AF_UNIX, SOCK_SEQPACKET, 0, (long)pair, 0, 0);
    char hello = 'c';
    struct broker_request *r = calloc(1, BROKER_MESSAGE_MAX);
    {
        char control[CMSG_SPACE(sizeof(int))];
        struct iovec io = {&hello, 1};
        struct msghdr m = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = control,
                           .msg_controllen = sizeof(control)};
        struct cmsghdr *h = CMSG_FIRSTHDR(&m);
        h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS; h->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(h), &pair[1], sizeof(int));
        report("channel", via(__NR_sendmsg, cfg->isolate_fd, (long)&m, 0, 0, 0, 0) < 0);
        close(pair[1]);
    }
    int ch = pair[0];
    char data[256];
    size_t n;
    /* A host path outside every tree, as if the payload had resolved it. */
    n = with_paths(r, __NR_openat, out, 1, 0, 0);
    r->args[0] = AT_FDCWD;
    data[0] = 0;
    report("f-open-outside", request(ch, r, n, 0, 0, data, sizeof(data)));
    if (data[0]) printf("data=%s\n", data);
    n = with_paths(r, __NR_openat, ro, 1, 0, 0);
    r->args[0] = AT_FDCWD; r->args[2] = O_RDWR;
    report("f-open-ro-rw", request(ch, r, n, 0, 0, 0, 0));
    n = with_paths(r, __NR_openat, "/../../../../../../etc/passwd", 1, 0, 0);
    r->args[0] = AT_FDCWD;
    report("f-open-dotdot", request(ch, r, n, 0, 0, 0, 0));
    char rwlink[512];
    snprintf(rwlink, sizeof(rwlink), "%s.hardlink", rw);
    n = with_paths(r, __NR_linkat, ro, 1, rwlink, 3);
    r->args[0] = r->args[2] = AT_FDCWD;
    report("f-link-ro-to-rw", request(ch, r, n, 0, 0, 0, 0));
    /* /proc/self/fd flag with no FD attached; with a directory FD it does not name. */
    n = with_paths(r, __NR_openat, "", 1, 0, 0);
    r->args[0] = AT_FDCWD; r->flags = BROKER_MAGIC(1);
    report("f-magic-nofd", request(ch, r, n, 0, 0, 0, 0));
    /* Lengths beyond the message, unknown call numbers, truncated messages. */
    n = with_paths(r, __NR_openat, rw, 1, 0, 0);
    r->args[0] = AT_FDCWD; r->len[1] = 60000;
    report("f-bad-length", request(ch, r, n, 0, 0, 0, 0));
    n = with_paths(r, __NR_openat, rw, 1, 0, 0);
    r->args[0] = AT_FDCWD; r->len[1] -= 1; /* not NUL-terminated */
    report("f-unterminated", request(ch, r, n, 0, 0, 0, 0));
    n = with_paths(r, __NR_execve, rw, 0, 0, 0);
    report("f-unknown-nr", request(ch, r, n, 0, 0, 0, 0));
    report("f-truncated", request(ch, r, 7, 0, 0, 0, 0));
    n = with_paths(r, __NR_openat, rw, 1, 0, 0);
    r->args[0] = AT_FDCWD; r->fds = 2; /* claims FDs it does not attach */
    report("f-fd-count", request(ch, r, n, 0, 0, 0, 0));
    /* A socket outside every tree. */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    n = with_paths(r, BROKER_CONNECT_PATH, sock, 1, 0, 0);
    report("f-connect-outside", request(ch, r, n, &s, 1, 0, 0));
    /* A raw UNIX path address through the "any address" form. */
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strncpy(a.sun_path, sock, sizeof(a.sun_path) - 1);
    memset(r, 0, sizeof(*r));
    r->nr = __NR_connect; r->args[2] = sizeof(a); r->len[1] = sizeof(a); r->fds = 1;
    memcpy(r + 1, &a, sizeof(a));
    report("f-connect-raw-path", request(ch, r, sizeof(*r) + sizeof(a), &s, 1, 0, 0));
    /* After all that the broker still serves a valid request. */
    n = with_paths(r, __NR_openat, rw, 1, 0, 0);
    r->args[0] = AT_FDCWD;
    report("f-valid-after", request(ch, r, n, 0, 0, 0, 0) >= 1000);
    open_read("f-hooked-after", "/rw/file", O_RDONLY);
}

/* The harness kills the broker processes between "ready" and the line it
 * then writes to stdin. */
static void after_broker_gone(const char *path)
{
    struct stat st;
    open_read("after", path, O_RDONLY);
    report("after-stat", hooked(__NR_newfstatat, AT_FDCWD, (long)path, (long)&st, 0, 0, 0));
    pid_t pid = fork();
    if (!pid) { open_read("after-child", path, O_RDONLY); _exit(0); }
    waitpid(pid, 0, 0);
}

static void killbroker(const char *path)
{
    char line[8];
    open_read("before", path, O_RDONLY);
    printf("ready\n");
    fflush(stdout);
    read(0, line, sizeof(line));
    after_broker_gone(path);
}

/* The payload's own FDs closed from its svc (past the payload's guard):
 * file access must fail, not fall back to direct calls. */
static void cutoff(const char *path)
{
    payload_config_t *cfg = payload_config();
    if (!cfg) { report("config-found", 0); return; }
    open_read("before", path, O_RDONLY);
    for (int fd = 900; fd < 964; fd++)
        via(__NR_close, fd, 0, 0, 0, 0, 0);
    report("close-control", via(__NR_close, cfg->isolate_fd, 0, 0, 0, 0, 0));
    after_broker_gone(path);
}

static void procs(void)
{
    pid_t parent = getppid();
    char path[64], buf[64];
    snprintf(path, sizeof(path), "/proc/%d/status", parent);
    open_read("proc-other-status", path, O_RDONLY);
    snprintf(path, sizeof(path), "/proc/%d/mem", parent);
    open_read("proc-other-mem", path, O_RDONLY);
    snprintf(path, sizeof(path), "/proc/%d/status", getpid());
    open_read("proc-self-status", path, O_RDONLY);
    open_read("proc-1-environ", "/proc/1/environ", O_RDONLY);
    struct iovec local = {buf, sizeof(buf)}, remote = {(void *)PAYLOAD_FIXED_BASE, sizeof(buf)};
    report("vm-readv", via(__NR_process_vm_readv, parent, (long)&local, 1, (long)&remote, 1, 0));
    report("vm-writev", via(__NR_process_vm_writev, parent, (long)&local, 1, (long)&remote, 1, 0));
    report("vm-readv-hooked", hooked(__NR_process_vm_readv, parent, (long)&local, 1, (long)&remote, 1, 0));
    report("ptrace", via(__NR_ptrace, 16, parent, 0, 0, 0, 0));
    long pidfd = via(434 /* pidfd_open */, parent, 0, 0, 0, 0, 0);
    report("pidfd-getfd", pidfd < 0 ? pidfd : via(__NR_pidfd_getfd, pidfd, 0, 0, 0, 0, 0));
    /* Seccomp field of this process (needs the /proc bind). */
    int fd = open("/proc/self/status", O_RDONLY);
    char st[4096];
    long k = fd < 0 ? 0 : read(fd, st, sizeof(st) - 1);
    st[k > 0 ? k : 0] = 0;
    char *line = strstr(st, "Seccomp:");
    if (line) printf("seccomp %ld\n", strtol(line + 8, 0, 10));
}

int main(int argc, char **argv)
{
    if (argc < 3) return 2;
    find_gadget();
    direct = argv[1][0] == 'd';
    const char *op = argv[2], *p = argc > 3 ? argv[3] : 0, *q = argc > 4 ? argv[4] : 0;
    if (!strcmp(op, "open")) open_read("open", p, (int)strtol(q, 0, 8));
    else if (!strcmp(op, "list")) list(p);
    else if (!strcmp(op, "exec")) {
        char *args[] = {(char *)p, 0}, *env[] = {0};
        long rc = direct ? via(281, AT_FDCWD, (long)p, (long)args, (long)env, 0, 0)
                         : hooked(__NR_execve, (long)p, (long)args, (long)env, 0, 0, 0);
        report("exec", rc);
    } else if (!strcmp(op, "execfd")) {
        long fd = hooked(__NR_openat, AT_FDCWD, (long)p, O_RDONLY, 0, 0, 0);
        report("open", fd < 0 ? fd : 0);
        char *args[] = {(char *)p, 0}, *env[] = {0};
        if (fd >= 0) report("execfd", hooked(281, fd, (long)"", (long)args, (long)env, AT_EMPTY_PATH, 0));
    } else if (!strcmp(op, "fdops")) fdops(p);
    else if (!strcmp(op, "bind") || !strcmp(op, "connect")) report(op, unix_socket(op, p));
    else if (!strcmp(op, "filter")) filter();
    else if (!strcmp(op, "tamper")) tamper(p, q, argv[5]);
    else if (!strcmp(op, "forge")) forge(p, q, argv[5], argv[6]);
    else if (!strcmp(op, "killbroker")) killbroker(p);
    else if (!strcmp(op, "cutoff")) cutoff(p);
    else if (!strcmp(op, "procs")) procs();
    else {
        long rc = path_op(op, p, q);
        if (rc == -9999) return 2;
        report(op, rc);
    }
    return 0;
}
