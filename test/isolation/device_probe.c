/* SPDX-License-Identifier: GPL-2.0-or-later */
/* --isolate-device acceptance probe (docs/ISOLATION.md, "GPU 设备", 验收标准).
 * Part of the application sandbox's acceptance suite: every check states an
 * expected outcome of the guest filter or the broker. Calls marked "d" are
 * issued from the payload's own `svc; ret` (the filter alone decides them),
 * "h" go through the payload and the broker. Prints "<label> <value>" with
 * the return value or -errno.
 *
 *   device_probe filter            filter rules (direct calls)
 *   device_probe broker LINK ALIAS loader file and /proc/<pid>/mem (payload
 *                                  path): LINK a hard link of the loader in a
 *                                  writable tree, ALIAS a case alias of it
 *   device_probe exec              execveat of the loader FD is allowed */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <asm/unistd.h>
#include "config.h"
#include "elf_abi.h"

#define PAGE 4096ul
static unsigned long gadget;

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

static void report(const char *label, long v) { printf("%s %ld\n", label, v); fflush(stdout); }

/* expr in a forked child: a call the host sandbox kills (SIGSYS) before
 * the guest filter answers reports -1000 - signal. */
static long *slot;
#define CHECK(label, expr) do { \
        pid_t pid_ = fork(); \
        if (!pid_) { *slot = (expr); _exit(0); } \
        int st_ = 0; \
        waitpid(pid_, &st_, 0); \
        report(label, WIFSIGNALED(st_) ? -1000 - WTERMSIG(st_) : *slot); \
    } while (0)

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

/* The loader's constant page: found by its magic in the loader's first
 * (read-only) segment. */
static char *page;
static char *empty_path(void) { return page + 16; }
static char *device(int i) { return page + 32 + 64 * i; }

static void find_page(void)
{
    for (char *p = (char *)LOADER_FIXED_BASE; p < (char *)LOADER_FIXED_BASE + 0x40000; p += PAGE)
        if (!memcmp(p, "elf-isolate-pg1", 16)) {
            page = p;
            return;
        }
    printf("page missing\n");
    exit(2);
}

static void filter_rules(void)
{
    const unsigned long g0 = (unsigned long)page;
    long fd;
    /* Control: the selected constant opens the device itself. */
    fd = via(__NR_openat, AT_FDCWD, (long)device(0), O_RDWR | O_CLOEXEC, 0, 0, 0);
    CHECK("open-selected", fd >= 0 ? 0 : fd);
    if (fd >= 0)
        via(__NR_close, fd, 0, 0, 0, 0, 0);
    fd = via(__NR_openat, 12345, (long)device(0), O_RDONLY | O_NONBLOCK | O_NOCTTY, 0, 0, 0);
    CHECK("open-selected-dirfd", fd >= 0 ? 0 : fd);
    if (fd >= 0)
        via(__NR_close, fd, 0, 0, 0, 0, 0);
    /* Refused: any other pointer, even to the same text. */
    char copy[64];
    strcpy(copy, device(0));
    CHECK("open-other-pointer", via(__NR_openat, AT_FDCWD, (long)copy, O_RDWR, 0, 0, 0));
    CHECK("open-high-bits", via(__NR_openat, AT_FDCWD, (long)device(0) + (1l << 32), O_RDWR, 0, 0, 0));
    CHECK("open-inside-constant", via(__NR_openat, AT_FDCWD, (long)device(0) + 4, O_RDWR, 0, 0, 0));
    static const struct { const char *name; long flags; } bad[] = {
        {"open-creat", O_RDWR | O_CREAT}, {"open-path", O_PATH}, {"open-trunc", O_RDWR | O_TRUNC},
        {"open-directory", O_RDONLY | O_DIRECTORY}, {"open-tmpfile", O_RDWR | O_TMPFILE},
        {"open-nofollow", O_RDWR | O_NOFOLLOW}, {"open-append", O_RDWR | O_APPEND},
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(bad[i].name, via(__NR_openat, AT_FDCWD, (long)device(0), bad[i].flags, 0, 0, 0));
    for (int i = 1; i < CONFIG_ISOLATE_DEVICES; i++) {
        char label[32];
        snprintf(label, sizeof label, "open-unselected-%d", i);
        CHECK(label, via(__NR_openat, AT_FDCWD, (long)device(i), O_RDWR, 0, 0, 0));
    }

    /* The constant page: every memory call that meets it is refused. */
    char *anon = mmap(0, 4 * PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK("munmap-page", via(__NR_munmap, g0, PAGE, 0, 0, 0, 0));
    CHECK("munmap-from-below", via(__NR_munmap, g0 - PAGE, 2 * PAGE, 0, 0, 0, 0));
    CHECK("munmap-wide", via(__NR_munmap, g0 - 0x100000, 0x200000, 0, 0, 0, 0));
    CHECK("mprotect-page", via(__NR_mprotect, g0, PAGE, PROT_READ | PROT_WRITE, 0, 0, 0));
    CHECK("mprotect-none", via(__NR_mprotect, g0, 1, PROT_NONE, 0, 0, 0));
    CHECK("pkey_mprotect-page", via(__NR_pkey_mprotect, g0, PAGE, PROT_READ | PROT_WRITE, -1, 0, 0));
    CHECK("madvise-page", via(__NR_madvise, g0, PAGE, MADV_DONTNEED, 0, 0, 0));
    CHECK("madvise-from-below", via(__NR_madvise, g0 - 2 * PAGE, 3 * PAGE, MADV_DONTNEED, 0, 0, 0));
    CHECK("remap_file_pages-page", via(__NR_remap_file_pages, g0, PAGE, 0, 0, 0, 0));
    CHECK("mmap-fixed-page", via(__NR_mmap, g0, PAGE, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
    CHECK("mmap-fixed-over", via(__NR_mmap, g0 - 0x10000, 0x20000, PROT_READ,
                                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0));
    CHECK("mremap-old", via(__NR_mremap, g0, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0, 0));
    CHECK("mremap-fixed-new", via(__NR_mremap, (long)anon, PAGE, PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, g0, 0));
    CHECK("mremap-fixed-new-below", via(__NR_mremap, (long)anon, 2 * PAGE, 2 * PAGE,
                                         MREMAP_MAYMOVE | MREMAP_FIXED, g0 - PAGE, 0));
    CHECK("shmat-remap", via(__NR_shmat, 0, g0, 040000 /* SHM_REMAP */, 0, 0, 0));
    CHECK("userfaultfd", via(__NR_userfaultfd, 0, 0, 0, 0, 0, 0));
    CHECK("unshare", via(__NR_unshare, 0, 0, 0, 0, 0, 0));
    CHECK("setns", via(__NR_setns, -1, 0, 0, 0, 0, 0));
    /* Allowed: next to it, and away from it. */
    CHECK("mprotect-before", via(__NR_mprotect, g0 - PAGE, PAGE, PROT_READ, 0, 0, 0));
    CHECK("mprotect-after", via(__NR_mprotect, g0 + PAGE, PAGE, PROT_READ, 0, 0, 0));
    CHECK("mmap-fixed-own", via(__NR_mmap, (long)anon, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                 -1, 0) == (long)anon ? 0 : -1);
    CHECK("mmap-hint-page", via(__NR_mmap, g0, PAGE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != (long)g0 ? 0 : -1);
    CHECK("munmap-own", via(__NR_munmap, (long)anon, 4 * PAGE, 0, 0, 0, 0));
    CHECK("page-intact", strcmp(device(0), "/dev/hvgr0") ? -1 : 0);

    /* execveat runs only the loader FD with the page's empty path. */
    char *argv[] = {"x", 0};
    CHECK("execveat-own-empty", via(__NR_execveat, CONFIG_ISOLATE_LOADER_FD, (long)"", (long)argv, 0, AT_EMPTY_PATH, 0));
    CHECK("execveat-other-fd", via(__NR_execveat, 0, (long)empty_path(), (long)argv, 0, AT_EMPTY_PATH, 0));
    CHECK("execveat-no-empty-flag", via(__NR_execveat, CONFIG_ISOLATE_LOADER_FD, (long)empty_path(), (long)argv, 0, 0, 0));
    CHECK("execveat-path", via(__NR_execveat, AT_FDCWD, (long)device(0), (long)argv, 0, 0, 0));
    CHECK("execve", via(__NR_execve, (long)device(0), (long)argv, 0, 0, 0, 0));

    /* The loader FD cannot be closed, replaced or marked close-on-exec. */
    int l = CONFIG_ISOLATE_LOADER_FD;
    CHECK("close-loader", via(__NR_close, l, 0, 0, 0, 0, 0));
    CHECK("close-loader-high-bits", via(__NR_close, (1l << 32) | l, 0, 0, 0, 0, 0));
    CHECK("dup3-onto-loader", via(__NR_dup3, 0, l, 0, 0, 0, 0));
    CHECK("fcntl-setfd-loader", via(__NR_fcntl, l, F_SETFD, FD_CLOEXEC, 0, 0, 0));
    CHECK("ioctl-fioclex-loader", via(__NR_ioctl, l, 0x5451, 0, 0, 0, 0));
    CHECK("close_range-over-loader", via(__NR_close_range, 800, 1000, 0, 0, 0, 0));
    CHECK("close_range-cloexec-loader", via(__NR_close_range, l, l, 4 /* CLOSE_RANGE_CLOEXEC */, 0, 0, 0));
    /* Allowed on it, and the same calls on other FDs. */
    CHECK("fcntl-getfd-loader", via(__NR_fcntl, l, F_GETFD, 0, 0, 0, 0));
    long spare = via(__NR_dup3, 0, 777, 0, 0, 0, 0);
    CHECK("dup3-other", spare == 777 ? 0 : spare);
    CHECK("fcntl-setfd-other", via(__NR_fcntl, 777, F_SETFD, FD_CLOEXEC, 0, 0, 0));
    CHECK("close-other", via(__NR_close, 777, 0, 0, 0, 0, 0));
    CHECK("close_range-away", via(__NR_close_range, 2000, 3000, 0, 0, 0, 0));
    CHECK("loader-fd-open", via(__NR_fcntl, l, F_GETFD, 0, 0, 0, 0) >= 0 ? 0 : -1);
}

/* The broker refuses writes to the loader file under any name, and
 * /proc/<pid>/mem. Through the payload (libc calls). */
static void broker_rules(const char *link, const char *alias)
{
    payload_config_t *cfg = payload_config();
    report("config-found", cfg != 0);
    const char *loader = cfg ? cfg->loader_path : "/";
    static const struct { const char *name; int flags; } modes[] = {
        {"rdwr", O_RDWR}, {"wronly", O_WRONLY}, {"trunc", O_WRONLY | O_TRUNC}, {"rdonly", O_RDONLY},
    };
    const char *paths[3][2] = {{"loader", loader}, {"link", link}, {"alias", alias}};
    for (int p = 0; p < 3; p++)
        for (unsigned m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
            char label[64];
            snprintf(label, sizeof label, "open-%s-%s", paths[p][0], modes[m].name);
            int fd = open(paths[p][1], modes[m].flags);
            report(label, fd >= 0 ? 0 : -errno);
            if (fd >= 0)
                close(fd);
        }
    report("truncate-link", truncate(link, 0) ? -errno : 0);
    report("chmod-link", chmod(link, 0777) ? -errno : 0);
    report("truncate-alias", truncate(alias, 0) ? -errno : 0);
    int ro = open(link, O_RDONLY);
    report("fchmod-link", fchmod(ro, 0777) ? -errno : 0);
    char self[64];
    snprintf(self, sizeof self, "/proc/self/fd/%d", ro);
    int re = open(self, O_RDWR);
    report("reopen-link-rdwr", re >= 0 ? 0 : -errno);
    snprintf(self, sizeof self, "/proc/self/fd/%d", CONFIG_ISOLATE_LOADER_FD);
    re = open(self, O_RDWR);
    report("reopen-loader-fd-rdwr", re >= 0 ? 0 : -errno);
    /* /proc/<pid>/mem writes through page protection. */
    char mem[64];
    int fd = open("/proc/self/mem", O_RDWR);
    report("proc-self-mem", fd >= 0 ? 0 : -errno);
    fd = open("/proc/self/mem", O_RDONLY);
    report("proc-self-mem-rdonly", fd >= 0 ? 0 : -errno);
    snprintf(mem, sizeof mem, "/proc/%d/mem", getpid());
    fd = open(mem, O_RDWR);
    report("proc-pid-mem", fd >= 0 ? 0 : -errno);
    snprintf(mem, sizeof mem, "/proc/%d/task/%d/mem", getpid(), gettid());
    fd = open(mem, O_RDWR);
    report("proc-task-mem", fd >= 0 ? 0 : -errno);
    fd = open("/proc/self/status", O_RDONLY);
    report("proc-status", fd >= 0 ? 0 : -errno);
    /* The device path keeps its names. */
    report("rename-device", rename("/dev/hvgr0", "/dev/hvgr0.x") ? -errno : 0);
    report("unlink-device", unlink("/dev/hvgr0") ? -errno : 0);
}

/* A forked child runs the loader FD with the page's empty path (the loader
 * prints its filter and exits 0): the allowed form really runs. */
static void exec_allowed(void)
{
    pid_t pid = fork();
    if (!pid) {
        char *argv[] = {"elfloader", "--guest-filter-dump", 0};
        long rc = via(__NR_execveat, CONFIG_ISOLATE_LOADER_FD, (long)empty_path(), (long)argv, (long)environ,
                      AT_EMPTY_PATH, 0);
        printf("execveat-failed %ld\n", rc);
        _exit(3);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    report("execveat-loader", WIFEXITED(status) ? WEXITSTATUS(status) : 100 + WTERMSIG(status));
}

int main(int argc, char **argv)
{
    find_gadget();
    find_page();
    slot = mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (argc > 1 && !strcmp(argv[1], "filter"))
        filter_rules();
    else if (argc > 3 && !strcmp(argv[1], "broker"))
        broker_rules(argv[2], argv[3]);
    else if (argc > 1 && !strcmp(argv[1], "exec"))
        exec_allowed();
    else
        return 2;
    return 0;
}
