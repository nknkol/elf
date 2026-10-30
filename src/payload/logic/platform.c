/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include "elf_abi.h"
#include "platform.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

int platform_is_harmonyos(void)
{
    static int cached = -1;
    if (cached < 0) {
        char u[6][65];
        static const char name[] = "HarmonyOS";
        cached = 0;
        if (raw_syscall(__NR_uname, (long)u, 0, 0, 0, 0, 0) >= 0) {
            size_t i = 0;
            while (i < sizeof(name) && u[0][i] == name[i]) i++;
            cached = i == sizeof(name);
        }
    }
    return cached;
}

long platform_mprotect_exec(unsigned long addr, size_t len, int prot)
{
    int jit = (prot & 4 /* PROT_EXEC */) && platform_is_harmonyos();
    if (jit) raw_syscall(__NR_prctl, PR_HM_JIT, 0, 0, 0, 0, 0);
    long rc = raw_syscall(__NR_mprotect, (long)addr, (long)len, prot, 0, 0, 0);
    if (jit) raw_syscall(__NR_prctl, PR_HM_JIT, 0, 1, 0, 0, 0);
    return rc;
}
