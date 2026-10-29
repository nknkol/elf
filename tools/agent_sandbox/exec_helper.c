/* SPDX-License-Identifier: GPL-2.0-or-later */
/* First guest program of an agent launch: enter the guest working directory,
 * then exec the requested guest command through the payload, so target,
 * shebang and PT_INTERP resolution use the same policy as any later exec.
 * argv: helper workdir path arg0 [args...]. Static, relocation-free code:
 * no libc, no initialized pointer data. */
#include <asm/unistd.h>
#include <errno.h>

#define PR_ELF_FD_QUERY 0x46445452

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

void run(long *stack)
{
    long argc = stack[0];
    char **argv = (char **)(stack + 1), **env = argv + argc + 1;
    if (argc < 4) fail("elf-exec: usage: helper workdir path arg0 [args...]", 0, 64);
    /* Natively this prctl is EINVAL. Refuse to run unconfined if the SVC
     * patch did not route this binary through the payload. */
    if (call(__NR_prctl, PR_ELF_FD_QUERY, 0, 0, 0) < 0)
        fail("elf-exec: payload interception is not active", 0, 70);
    long rc = call(__NR_chdir, (long)argv[1], 0, 0, 0);
    if (rc < 0) fail("elf-exec: cannot enter working directory", rc, 66);
    rc = call(__NR_execve, (long)argv[2], (long)(argv + 3), (long)env, 0);
    fail("elf-exec: exec failed", rc, rc == -ENOENT ? 127 : 126);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
