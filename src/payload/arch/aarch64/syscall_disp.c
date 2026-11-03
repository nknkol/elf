#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include "syscall_nums.h"
#include "dispatch.h"
#include "integrity.h"
#include "config.h"
#include "proot_bridge.h"
#include "container_state.h"
#include "union_view.h"
#include "net_view.h"
#include "fake_ids.h"
#include "host_syscall.h"
#ifdef GUARDED
#include "fd_runtime.h"
#define DISPATCH(n, args) fd_runtime_dispatch(n, args)
#else
#define DISPATCH(n, args) dispatch_syscall(n, args)
#endif

typedef struct {
    unsigned long regs[30]; // x0 - x29
    unsigned long lr;       // x30
    unsigned long _pad;
} pt_regs;

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

/* Runs on a payload stack (payload_stack.c), with regs (the saved general
 * registers) on the guest's. */
long syscall_dispatcher(long sys_no, pt_regs *regs)
{
    long *a = (long *)regs->regs;
    /* A thread unmapping the stack it entered on (musl's __unmapself: munmap
     * then exit, touching no stack): nothing can return to it, since the
     * entry saved the registers there. Its only next step is exit. */
    if (sys_no == __NR_munmap && (unsigned long)regs - (unsigned long)a[0] < (unsigned long)a[1]) {
        long rc = raw_syscall(__NR_munmap, a[0], a[1], 0, 0, 0, 0);
        if (!rc)
            raw_syscall(__NR_exit, 0, 0, 0, 0, 0, 0);
        return rc;
    }
    /* The backends may rewrite their copy; the saved registers stay. */
    long args[6] = {a[0], a[1], a[2], a[3], a[4], a[5]};
    long ret;

    if (sys_no >= __NR_setxattrat && sys_no <= __NR_file_setattr)
        return -ENOSYS; /* Untranslated newer path calls (syscall_nums.h). */
    if (integrity_check(sys_no, a, &ret))
        return ret;
    int named = sys_no == __NR_accept || sys_no == __NR_accept4 ||
        sys_no == __NR_getsockname || sys_no == __NR_getpeername;
    unsigned capacity = named && a[1] && a[2] ? *(unsigned *)a[2] : 0;
    /* R6: loop devices are the payload's (before the guarded ioctl policy). */
    if (sys_no == __NR_ioctl && mounts_enabled() && proot_loop_ioctl(a[0], (unsigned long)a[1], a[2], &ret))
        return ret;
    ret = DISPATCH(sys_no, args);
    /* R6: a directory of the merged view lists every layer. */
    if (sys_no == __NR_getdents64 && union_enabled())
        ret = union_getdents((int)a[0], (void *)a[1], (unsigned long)a[2], ret);
    /* A batch holding only the payload's FDs is read again: zero means the
     * end of the directory. */
    while (sys_no == __NR_getdents64 && ret > 0 && !(ret = broker_hide_fds((int)a[0], (void *)a[1], ret))) {
        long again[6] = {a[0], a[1], a[2], a[3], a[4], a[5]};
        ret = DISPATCH(sys_no, again);
    }
    /* R6: an openat2 lookup may be the kernel's own (RESOLVE_BENEATH, or
     * passed through): a layer image placeholder is filled all the same. */
    if (sys_no == __NR_openat2 && ret >= 0 && union_enabled()) {
        long fill = union_lazy_fd((int)ret);
        if (fill < 0) {
            long close_args[6] = {ret, 0, 0, 0, 0, 0};
            DISPATCH(__NR_close, close_args);
            ret = fill;
        }
    }
    if (!ret) {
        fake_ids_stat_owner(sys_no, a);
        owners_stat(sys_no, a); /* R5: recorded owners and modes */
        union_lazy_stat(sys_no, a); /* R6: layer image placeholders */
    }
    /* struct utsname: six 65-byte fields; sysname, nodename, release. */
    if (!ret && sys_no == __NR_uname && a[0]) {
        if (g_payload_config.kernel_sysname[0])
            memcpy((char *)a[0], g_payload_config.kernel_sysname, 65);
        if (g_payload_config.hostname[0])
            memcpy((char *)a[0] + 65, g_payload_config.hostname, 65);
        if (g_payload_config.kernel_release[0])
            memcpy((char *)a[0] + 130, g_payload_config.kernel_release, 65);
    }
    if (ret >= 0 && capacity)
        proot_socket_name(sys_no, sys_no == __NR_accept || sys_no == __NR_accept4 ? ret : a[0],
                          (void *)a[1], (unsigned *)a[2], capacity);
    /* Container networks: ports of the container's addresses as the guest
     * bound them (net_view.h). */
    if (ret >= 0 && net_enabled()) {
        if (named && a[1] && a[2])
            net_reverse((void *)a[1], *(unsigned *)a[2] < capacity ? *(unsigned *)a[2] : capacity);
        else if (sys_no == __NR_recvfrom && a[4] && a[5])
            net_reverse((void *)a[4], *(unsigned *)a[5]);
        else if (sys_no == __NR_recvmsg && a[1]) {
            void *msg_name = *(void **)a[1];
            int msg_length = *(int *)((char *)a[1] + 8);
            if (msg_name && msg_length > 0) net_reverse(msg_name, (unsigned)msg_length);
        }
    }
    return ret;
}
