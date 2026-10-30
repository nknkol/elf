/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Guest syscalls after the integrity checks: PRoot path semantics (the
 * bridge), fake credentials, hooking of newly executable memory, the calls
 * this platform cannot serve, and native passthrough for everything else. */
#include "syscall_nums.h"
#include <errno.h>
#include <stddef.h>
#include "config.h"
#include "dispatch.h"
#include "elf_abi.h"
#include "fake_ids.h"
#include "hook_runtime.h"
#include "platform.h"
#include "proot_bridge.h"

#define PROT_READ     0x1
#define PROT_WRITE    0x2
#define PROT_EXEC     0x4
#define MAP_ANONYMOUS 0x20

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);
extern void _start(void);

static long passthrough(long number, const long a[6])
{
    return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* Reads [off, off+len) of fd into dst; the tail past end of file is zero. */
static long read_region(int fd, unsigned char *dst, unsigned long len, long off)
{
    while (len) {
        unsigned long chunk = len > 4096 ? 4096 : len;
        long n = raw_syscall(__NR_pread64, fd, (long)dst, (long)chunk, off, 0, 0);
        if (n < 0)
            return n;
        if (n == 0) {
            for (unsigned long i = 0; i < len; i++)
                dst[i] = 0;
            break;
        }
        dst += n;
        off += n;
        len -= (unsigned long)n;
    }
    return 0;
}

/* An executable file mapping becomes an anonymous copy (code signing
 * refuses executable file pages on HarmonyOS), patched while writable and
 * made executable once. Fail closed: no unhooked syscall is left runnable. */
static long map_exec_copy(const long a[6])
{
    unsigned long len = (unsigned long)a[1];
    int prot = (int)a[2], fd = (int)a[4];
    long mapped = raw_syscall(__NR_mmap, a[0], (long)len, PROT_READ | PROT_WRITE,
                              a[3] | MAP_ANONYMOUS, -1, 0);
    if (mapped < 0)
        return mapped;
    long rc = read_region(fd, (unsigned char *)mapped, len, a[5]);
    if (rc >= 0 && install_hook_file((void *)mapped, len, (void *)&_start,
                                     PROT_READ | PROT_WRITE, fd, (unsigned long)a[5]) < 0)
        rc = -ENOMEM;
    if (rc >= 0)
        rc = platform_mprotect_exec(mapped, len, prot);
    if (rc < 0) {
        raw_syscall(__NR_munmap, mapped, (long)len, 0, 0, 0, 0);
        return rc;
    }
    return mapped;
}

/* Executable memory is readable (the hook scanner reads it) and hooked
 * before any of it can run. */
static long map_exec(long number, long a[6])
{
    a[2] |= PROT_READ;
    if (number == __NR_mmap && !(a[3] & MAP_ANONYMOUS) && (int)a[4] >= 0)
        return map_exec_copy(a);
    long ret = number == __NR_mmap ? passthrough(number, a) :
        platform_mprotect_exec(a[0], (unsigned long)a[1], (int)a[2]);
    if (ret < 0)
        return ret;
    unsigned long base = number == __NR_mmap ? (unsigned long)ret : (unsigned long)a[0];
    if (install_hook_prot((void *)base, (size_t)a[1], (void *)&_start, (int)a[2]) < 0) {
        /* Fail closed: drop the mapping (or its execute right). */
        if (number == __NR_mmap)
            raw_syscall(__NR_munmap, (long)base, a[1], 0, 0, 0, 0);
        else
            raw_syscall(__NR_mprotect, (long)base, a[1], a[2] & ~PROT_EXEC, 0, 0, 0);
        return -ENOMEM;
    }
    return number == __NR_mmap ? ret : 0;
}

long dispatch_syscall(long number, long a[6])
{
    if (number == __NR_prctl && a[0] == PR_GET_AUXV)
        return proot_get_auxv(a);
    if (number == __NR_execve || number == __NR_execveat)
        return proot_execve(number, a);
    if (proot_handles_syscall(number))
        return proot_syscall(number, a);
    long faked;
    if (fake_ids_syscall(number, a, &faked))
        return faked;
    switch (number) {
    case __NR_mmap:
    case __NR_mprotect:
        if (a[2] & PROT_EXEC)
            return map_exec(number, a);
        return passthrough(number, a);
    /* glibc falls back from both; the sandbox kills rseq with SIGSYS. */
    case __NR_rseq:
    case __NR_clone3:
        return -ENOSYS;
    /* The HarmonyOS sandbox kills these with SIGSYS: report them as not
     * implemented instead. Other kernels serve them natively. */
    case __NR_mount: case __NR_umount2: case __NR_pivot_root: case __NR_chroot:
    case __NR_unshare: case __NR_setns: case __NR_kcmp: case __NR_fchmodat2:
    case __NR_close_range: case __NR_openat2: case __NR_open_by_handle_at:
    case __NR_io_uring_enter: case __NR_io_uring_register:
        return platform_is_harmonyos() ? -ENOSYS : passthrough(number, a);
    default:
        return passthrough(number, a);
    }
}
