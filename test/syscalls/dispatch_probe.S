/* Real entry selector, deterministic C-dispatch test double. */
#include "syscall_nums.h"
.text
.global _start
_start:
    adr x19, selected
    adr x21, selected_end
1:
    cmp x19, x21
    b.eq 2f
    ldr w22, [x19], #4
    mov x8, x22
    mov x0, #71
    bl hook_entry
    add x20, x22, #1024
    cmp x0, x20
    b.ne fail
    b 1b
2:
    mov x8, #SYS_getpid
    bl hook_entry
    mov x20, x0
    mov x8, #SYS_getpid
    svc #0
    cmp x0, x20
    b.ne fail
    mov x8, #1023
    bl hook_entry
    cmn x0, #38
    b.ne fail
    /* A slow-dispatched exit would return the sentinel instead of exiting. */
    mov x0, #0
    mov x8, #SYS_exit_group
    bl hook_entry
fail:
    mov x0, #1
    mov x8, #SYS_exit_group
    svc #0
.global syscall_dispatcher
syscall_dispatcher:
    add x0, x0, #1024
    ret
.global reentry_try_enter
reentry_try_enter:
    mov x0, #1
    ret
.global reentry_leave
reentry_leave:
    ret
.data
.global g_payload_config
g_payload_config:
    .quad 0
selected:
#define SLOW_SYSCALL(n) .word n
#include "slow_syscalls.inc"
selected_end:
