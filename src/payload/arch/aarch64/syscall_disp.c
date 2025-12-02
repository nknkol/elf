#include "syscall_hooks.h"

typedef struct {
    unsigned long regs[30]; // x0 - x29
    unsigned long lr;       // x30
    unsigned long _pad;
} pt_regs;

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

long syscall_dispatcher(long sys_no, pt_regs *regs)
{
    long *a = (long *)regs->regs;
    long args[6];

    /* Copy original args to a scratch array so we don't mutate saved regs */
    args[0] = a[0];
    args[1] = a[1];
    args[2] = a[2];
    args[3] = a[3];
    args[4] = a[4];
    args[5] = a[5];

    /* Special case: infinite loop prevention */
    if (sys_no == SYS_write) {
        return raw_syscall(sys_no, a[0], a[1], a[2], a[3], a[4], a[5]);
    }

    return syscall_handle_common(sys_no, args);
}
