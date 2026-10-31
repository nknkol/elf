/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include "config.h"
#include "hook_runtime.h"
#include "host_syscall.h"
#include "integrity.h"

#define MAP_FIXED              0x10
#define MAP_FIXED_NOREPLACE    0x100000
#define MREMAP_FIXED           2
#define SIGSYS                 31

/* madvise advice that discards or replaces contents. */
static int destructive_advice(int advice)
{
    switch (advice) {
    case 4:  /* MADV_DONTNEED */
    case 8:  /* MADV_FREE */
    case 9:  /* MADV_REMOVE */
    case 10: /* MADV_DONTFORK */
    case 18: /* MADV_WIPEONFORK */
        return 1;
    default:
        return 0;
    }
}

static int touches_protected(long number, const long a[6])
{
    switch (number) {
    case __NR_munmap: case __NR_mprotect: case __NR_pkey_mprotect:
        break;
    case __NR_mremap:
        if ((a[3] & MREMAP_FIXED) && hook_protected_overlap((uintptr_t)a[4], (size_t)a[2]))
            return 1;
        break;
    case __NR_mmap:
        if (!(a[3] & MAP_FIXED) || (a[3] & MAP_FIXED_NOREPLACE))
            return 0;
        break;
    case __NR_madvise:
        if (!destructive_advice((int)a[2]))
            return 0;
        break;
    default:
        return 0;
    }
    return hook_protected_overlap((uintptr_t)a[0], (size_t)a[1]);
}

/* A guest SIGSYS action is recorded and reported back, never installed
 * (signals the guest raises itself are then not delivered to it). */
static unsigned char guest_sigsys[32];
static long sigsys_action(const long a[6])
{
    if (a[3] != 8)
        return -EINVAL;
    unsigned char previous[32];
    memcpy(previous, guest_sigsys, sizeof(previous));
    if (a[1]) memcpy(guest_sigsys, (const void *)a[1], sizeof(guest_sigsys));
    if (a[2]) memcpy((void *)a[2], previous, sizeof(previous));
    return 0;
}

int integrity_check(long number, const long a[6], long *result)
{
    if (touches_protected(number, a)) {
        *result = -EPERM;
        return 1;
    }
    if (broker_fd_guard(number, a, result))
        return 1;
    if (g_payload_config.seccomp_backstop && number == __NR_rt_sigaction && (int)a[0] == SIGSYS) {
        *result = sigsys_action(a);
        return 1;
    }
    return 0;
}
