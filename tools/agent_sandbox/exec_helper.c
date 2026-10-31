/* SPDX-License-Identifier: GPL-2.0-or-later */
/* First guest program of an agent launch or a container (tools/oci): enter
 * the guest working directory, then exec the requested guest command
 * through the payload, so target, shebang and PT_INTERP resolution use the
 * same policy as any later exec. A path without "/" is looked up in the
 * guest's PATH, as a container runtime does.
 * argv: helper workdir path arg0 [args...]. Static, relocation-free code:
 * no libc, no initialized pointer data. */
#include <asm/unistd.h>
#include <errno.h>

#include "elf_abi.h"

static long call(long n, long a, long b, long c, long d)
{
    register long x0 __asm__("x0") = a, x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c, x3 __asm__("x3") = d, x8 __asm__("x8") = n;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
                     : "memory", "cc");
    return x0;
}

static void fail(const char *message, long error, int status)
{
    long length = 0;
    while (message[length]) length++;
    call(__NR_write, 2, (long)message, length, 0);
    if (error < 0) {
        char digits[24];
        long value = -error, at = sizeof(digits);
        digits[--at] = '\n';
        do { digits[--at] = (char)('0' + value % 10); value /= 10; } while (value);
        digits[--at] = '-';
        digits[--at] = ' ';
        call(__NR_write, 2, (long)digits + at, (long)sizeof(digits) - at, 0);
    } else {
        call(__NR_write, 2, (long)"\n", 1, 0);
    }
    call(__NR_exit_group, status, 0, 0, 0);
    for (;;) {}
}

/* Copy loops may be compiled into these calls (no libc here). */
void *memcpy(void *to, const void *from, unsigned long n)
{
    volatile char *d = to;
    const volatile char *s = from;
    while (n--) *d++ = *s++;
    return to;
}
void *memset(void *to, int c, unsigned long n)
{
    volatile char *d = to;
    while (n--) *d++ = (char)c;
    return to;
}

static long length_of(const char *s)
{
    long n = 0;
    while (s[n]) n++;
    return n;
}

/* execvp: every PATH entry in turn; EACCES is remembered (126), a missing
 * file goes on (127 at the end). */
static void exec_path(const char *name, char **argv, char **env)
{
    const char *path = 0;
    for (char **e = env; *e; e++)
        if ((*e)[0] == 'P' && (*e)[1] == 'A' && (*e)[2] == 'T' && (*e)[3] == 'H' && (*e)[4] == '=')
            path = *e + 5;
    /* A literal is PC-relative: no relocation. */
    if (!path) path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    long name_length = length_of(name), denied = 0;
    char full[4096];
    for (const char *p = path;; p++) {
        const char *start = p;
        while (*p && *p != ':') p++;
        long dir = p - start;
        if (dir + 1 + name_length < (long)sizeof(full)) {
            long at = 0;
            for (long i = 0; i < dir; i++) full[at++] = start[i];
            if (!dir) full[at++] = '.';
            full[at++] = '/';
            for (long i = 0; i <= name_length; i++) full[at++] = name[i];
            long rc = call(__NR_execve, (long)full, (long)argv, (long)env, 0);
            if (rc == -EACCES) denied = 1;
            else if (rc != -ENOENT && rc != -ENOTDIR) fail("elf-exec: exec failed", rc, 126);
        }
        if (!*p) break;
    }
    fail(denied ? "elf-exec: permission denied" : "elf-exec: command not found", 0, denied ? 126 : 127);
}

void run(long *stack)
{
    long argc = stack[0];
    char **argv = (char **)(stack + 1), **env = argv + argc + 1;
    if (argc < 4) fail("elf-exec: usage: helper workdir path arg0 [args...]", 0, 64);
    /* Natively this prctl is EINVAL. Refuse to run unconfined if the SVC
     * patch did not route this binary through the payload. */
    long auxv[2];
    if (call(__NR_prctl, PR_ELF_FD_QUERY, 0, 0, 0) < 0 &&
        call(__NR_prctl, PR_GET_AUXV, (long)auxv, sizeof(auxv), 0) < 0)
        fail("elf-exec: payload interception is not active", 0, 70);
    long rc = call(__NR_chdir, (long)argv[1], 0, 0, 0);
    if (rc < 0) fail("elf-exec: cannot enter working directory", rc, 66);
    const char *path = argv[2];
    int slash = 0;
    for (const char *c = path; *c; c++) slash |= *c == '/';
    if (!slash) exec_path(path, argv + 3, env);
    rc = call(__NR_execve, (long)argv[2], (long)(argv + 3), (long)env, 0);
    fail("elf-exec: exec failed", rc, rc == -ENOENT ? 127 : 126);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
