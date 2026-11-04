/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include "stub.h"
.text
/* Called only by the dedicated generated clone stub. Its 32-byte frame holds
 * the original x16/x17/x30; x16 points to stub data. No clone executes inside
 * a C frame. The raw SVC sees the original guest SP and unchanged arguments.
 *
 * The guest's stack holds only the general registers (CLONE_CTX): the C
 * calls run on a payload stack, with the SIMD and FP control registers saved
 * there (call_on_payload_stack), as in entry.S. A Go program clones with
 * CLONE_VFORK and no new stack from a goroutine, whose stack has a few
 * hundred bytes below SP; parent and child both run this code on it. */
/* x0-x30 and the continuation (248); 256-271 take the parent's x16/x17 on
 * the way back (return_to_clone_stub). */
.equ CLONE_CTX, 272
.equ VECTOR_CTX, 528
.macro save_gprs
    sub sp, sp, #CLONE_CTX
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
.endm
.macro restore_gprs
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
.endm
/* fn(x0, x1, x2) on a payload stack (none free: this one), the SIMD and FP
 * control registers kept; its two result words stay in x0/x1. Uses
 * x19-x23, which the frame on the guest stack holds for the guest. */
.macro call_on_payload_stack fn
    mov x19, x0
    mov x20, x1
    mov x21, x2
    bl payload_stack_claim      /* general registers only */
    mov x22, x0
    mov x23, sp
    cbz x0, 1f
    mov sp, x0
1:
    sub sp, sp, #VECTOR_CTX
    stp q0, q1, [sp, #0]
    stp q2, q3, [sp, #32]
    stp q4, q5, [sp, #64]
    stp q6, q7, [sp, #96]
    stp q8, q9, [sp, #128]
    stp q10, q11, [sp, #160]
    stp q12, q13, [sp, #192]
    stp q14, q15, [sp, #224]
    stp q16, q17, [sp, #256]
    stp q18, q19, [sp, #288]
    stp q20, q21, [sp, #320]
    stp q22, q23, [sp, #352]
    stp q24, q25, [sp, #384]
    stp q26, q27, [sp, #416]
    stp q28, q29, [sp, #448]
    stp q30, q31, [sp, #480]
    mrs x0, fpcr
    mrs x1, fpsr
    str x0, [sp, #512]
    str x1, [sp, #520]
    mov x0, x19
    mov x1, x20
    mov x2, x21
    bl \fn
    mov x19, x0
    mov x20, x1
    ldr x0, [sp, #512]
    ldr x1, [sp, #520]
    msr fpcr, x0
    msr fpsr, x1
    ldp q0, q1, [sp, #0]
    ldp q2, q3, [sp, #32]
    ldp q4, q5, [sp, #64]
    ldp q6, q7, [sp, #96]
    ldp q8, q9, [sp, #128]
    ldp q10, q11, [sp, #160]
    ldp q12, q13, [sp, #192]
    ldp q14, q15, [sp, #224]
    ldp q16, q17, [sp, #256]
    ldp q18, q19, [sp, #288]
    ldp q20, q21, [sp, #320]
    ldp q22, q23, [sp, #352]
    ldp q24, q25, [sp, #384]
    ldp q26, q27, [sp, #416]
    ldp q28, q29, [sp, #448]
    ldp q30, q31, [sp, #480]
    mov sp, x23
    mov x0, x22
    bl payload_stack_release    /* general registers only */
    mov x0, x19
    mov x1, x20
.endm
/* Return via a stub-local direct branch. That stub restores x16/x17 from
 * the current parent/child stack, so no register is sacrificed to hold PC. */
.macro return_to_clone_stub offset
    ldp x10, x11, [sp, #128]
    str x10, [sp, #\offset]
    str x11, [sp, #(\offset + 8)]
    restore_gprs
    ldr x16, [sp, #248]
    add sp, sp, #\offset
    br x16
.endm
.global clone_entry
.type clone_entry,%function
clone_entry:
    mov w8, w8 /* The kernel's int syscall number, as in entry.S. */
    save_gprs
    /* Save continuation, then repair the two registers used by the stub. */
    sub x1, x16, #(STUB_DATA_OFFSET - STUB_CLONE_RESUME_OFFSET)
    str x1, [sp, #248]
    ldr x10, [sp, #CLONE_CTX]
    ldr x11, [sp, #(CLONE_CTX + 8)]
    stp x10, x11, [sp, #128]
    ldr x0, [sp, #72]           /* original x9 */
    ldr x2, [sp, #0]            /* clone flags */
    call_on_payload_stack clone_notify_prepare
    tbnz x0, #63, prepare_failed
    str x0, [sp, #72]           /* carry transaction in x9 across SVC */
    restore_gprs
    add sp, sp, #(CLONE_CTX + 32)
    svc #0
    /* Now SP is the parent's original SP or the child's requested new SP.
     * The child leaves CLONE_CHILD_KEEP bytes below its SP untouched: as
     * after a kernel clone, what the program put there before the call is
     * still there (Go's runtime.clone reads m, g, fn and a magic word from
     * just below the new stack). */
    cbnz x0, 1f
    sub sp, sp, #CLONE_CHILD_KEEP
1:
    save_gprs
    mov x1, x0                 /* kernel result */
    mov x0, x9                 /* transaction */
    call_on_payload_stack clone_notify_finish
    str x0, [sp, #72]           /* restore original x9 */
    ldr x2, [sp, #0]            /* kernel result: 0 in the child */
    cbz x2, child_return
    str x1, [sp, #248]          /* stub continuation */
    return_to_clone_stub (CLONE_CTX - 16)
child_return:
    add x1, x1, #(STUB_CLONE_CHILD_RESUME_OFFSET - STUB_CLONE_RESUME_OFFSET)
    str x1, [sp, #248]
    return_to_clone_stub CLONE_CTX
prepare_failed:
    str x0, [sp, #0]
    return_to_clone_stub (CLONE_CTX + 16)
.size clone_entry,.-clone_entry
.section .note.GNU-stack,"",@progbits
