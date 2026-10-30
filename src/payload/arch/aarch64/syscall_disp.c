#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include "syscall_nums.h"
#include "dispatch.h"
#include "integrity.h"
#include "config.h"
#include "proot_bridge.h"
#include "fake_ids.h"
#ifdef GUARDED
#include "fd_runtime.h"
#endif

typedef struct {
    unsigned long regs[30]; // x0 - x29
    unsigned long lr;       // x30
    unsigned long _pad;
} pt_regs;

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

long syscall_dispatcher(long sys_no, pt_regs *regs)
{
    long *a = (long *)regs->regs;
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
#ifdef GUARDED
    ret = fd_runtime_dispatch(sys_no, args);
#else
    ret = dispatch_syscall(sys_no, args);
#endif
    if (!ret) fake_ids_stat_owner(sys_no, a);
    /* struct utsname: six 65-byte fields; sysname first, release third. */
    if (!ret && sys_no == __NR_uname && a[0]) {
        if (g_payload_config.kernel_sysname[0])
            memcpy((char *)a[0], g_payload_config.kernel_sysname, 65);
        if (g_payload_config.kernel_release[0])
            memcpy((char *)a[0] + 130, g_payload_config.kernel_release, 65);
    }
    if (ret >= 0 && capacity)
        proot_socket_name(sys_no, sys_no == __NR_accept || sys_no == __NR_accept4 ? ret : a[0],
                          (void *)a[1], (unsigned *)a[2], capacity);
    return ret;
}
