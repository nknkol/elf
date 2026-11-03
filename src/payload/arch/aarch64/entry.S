.text
    .align 4
    .global _start
    .extern g_payload_config

#include "syscall_nums.h"
#include "stub.h"

/* The guest's stack holds only the saved general registers (the pt_regs
 * the dispatcher reads and writes); the SIMD registers and every C frame
 * after the two small general-registers-only calls go on a payload stack
 * (payload_stack.c says why). */
.equ    GPR_SIZE,       256
.equ    SIMD_SIZE,      512

_start:
    b       real_entry

    /* Payload Header: used by loader to find config block */
    .word   0x484F4F4B          /* Magic: "HOOK" */
    .word   g_payload_config - _start /* Offset to config struct */
    .word   PAYLOAD_ABI_VERSION /* elf_abi.h */

    /* Fixed offset 16, used only by the dedicated clone stub. */
    b clone_entry
real_entry:
    /* The kernel takes the syscall number as the int in w8: decide on the
     * same 32 bits (high bits must not route a known call past the slow
     * path). The guest's x8 upper half is not preserved by this entry. */
    mov     w8, w8
    /* rt_sigreturn must see the original user stack; bypass */
    cmp     x8, #__NR_rt_sigreturn
    b.eq    fast_path_sigreturn

    /* Direct entry callers keep raw clone. PRoot generated stubs use the
     * separate notification gate; legacy stubs bypass before touching SP.
     * Never execute clone inside the ordinary dispatcher/guard C frames. */
    cmp     x8, #__NR_clone
#ifdef GUARDED
    b.eq    slow_path
#else
    b.eq    fast_passthrough
#endif

#define SLOW_SYSCALL(n) cmp x8, n; b.eq slow_path
#ifdef GUARDED
#include "fd_runtime_syscalls.inc"
#endif
#include "slow_syscalls.inc"
#undef SLOW_SYSCALL
    b       fast_passthrough

slow_path:
    sub     sp, sp, #GPR_SIZE
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]

    /* Reentry guard: bail out if this thread is already inside the hook.
     * Built general-registers-only, as payload_stack_claim: the SIMD
     * registers are not saved yet. */
    bl      reentry_try_enter
#ifdef GUARDED
    cbnz    x0, 1f
    mov     x0, #-35 /* EDEADLK; never bypass nested metadata mutations */
    b       guard_error
1:
#else
    cbz     x0, reentry_bypass
#endif
    tbnz    x0, #63, guard_error
    mov     x19, x0
    ldr     x21, [x19] /* Owner TID: leave releases only its own lease. */

    /* Onto a payload stack (none: stay on this one). x23 = the saved
     * general registers, x22 = the stack to give back. */
    bl      payload_stack_claim
    mov     x22, x0
    mov     x23, sp
    cbz     x0, 2f
    mov     sp, x0
2:
    sub     sp, sp, #SIMD_SIZE
    stp     q0, q1, [sp, #0]
    stp     q2, q3, [sp, #32]
    stp     q4, q5, [sp, #64]
    stp     q6, q7, [sp, #96]
    stp     q8, q9, [sp, #128]
    stp     q10, q11, [sp, #160]
    stp     q12, q13, [sp, #192]
    stp     q14, q15, [sp, #224]
    stp     q16, q17, [sp, #256]
    stp     q18, q19, [sp, #288]
    stp     q20, q21, [sp, #320]
    stp     q22, q23, [sp, #352]
    stp     q24, q25, [sp, #384]
    stp     q26, q27, [sp, #416]
    stp     q28, q29, [sp, #448]
    stp     q30, q31, [sp, #480]

    /* Call dispatcher: x0=syscall no, x1=pt_regs (the syscall number as
     * saved: the calls above clobbered x8) */
    ldr     x0, [x23, #64]
    mov     x1, x23
    bl      syscall_dispatcher
    mov     x20, x0

    ldp     q30, q31, [sp, #480]
    ldp     q28, q29, [sp, #448]
    ldp     q26, q27, [sp, #416]
    ldp     q24, q25, [sp, #384]
    ldp     q22, q23, [sp, #352]
    ldp     q20, q21, [sp, #320]
    ldp     q18, q19, [sp, #288]
    ldp     q16, q17, [sp, #256]
    ldp     q14, q15, [sp, #224]
    ldp     q12, q13, [sp, #192]
    ldp     q10, q11, [sp, #160]
    ldp     q8, q9, [sp, #128]
    ldp     q6, q7, [sp, #96]
    ldp     q4, q5, [sp, #64]
    ldp     q2, q3, [sp, #32]
    ldp     q0, q1, [sp, #0]
    mov     sp, x23
    /* After the SIMD registers are back: general-registers-only calls. */
    mov     x0, x22
    bl      payload_stack_release
    mov     x0, x19
    mov     x1, x21
    bl      reentry_leave_owned
    mov     x0, x20
guard_error:
    /* Errors return to the guest without executing its syscall. */
    str     x0, [sp, #0]
    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #GPR_SIZE
    br      x30

reentry_bypass:
    /* Already handling a syscall in this thread: restore state and fall back */
    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9, [sp, #64]
    ldp     x6, x7, [sp, #48]
    ldp     x4, x5, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #GPR_SIZE
    b       fast_passthrough

fast_passthrough:
    svc     #0
    br      x30

fast_path_sigreturn:
    svc     #0
    br      x30
