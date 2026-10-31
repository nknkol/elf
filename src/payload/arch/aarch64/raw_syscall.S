.text
    .align 4
    .global raw_syscall

/*
 * long raw_syscall(long sys_no, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6)
 *
 * C calling convention (AArch64):
 * x0: sys_no
 * x1: arg1
 * x2: arg2
 * ...
 * x6: arg6
 *
 * Kernel ABI:
 * x8: sys_no
 * x0: arg1
 * ...
 * x5: arg6
 */
raw_syscall:
    /* Shuffle registers into kernel ABI */
    mov x8, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    mov x4, x5
    mov x5, x6

    svc #0
    ret

    .align 4
    .global call_on_stack

/*
 * long call_on_stack(long (*fn)(void *), void *arg, void *top)
 *
 * fn(arg) with sp at top (16-byte aligned), back on the caller's stack
 * when it returns.
 */
call_on_stack:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov sp, x2
    mov x16, x0
    mov x0, x1
    blr x16
    mov sp, x29
    ldp x29, x30, [sp], #16
    ret
