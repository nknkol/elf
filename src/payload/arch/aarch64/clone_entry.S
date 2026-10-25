/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include "stub.h"
.text
/* Called only by the dedicated generated clone stub. Its 32-byte frame holds
 * the original x16/x17/x30; x16 points to stub data. No clone executes inside
 * a C frame. The raw SVC sees the original guest SP and unchanged arguments. */
.equ CLONE_CTX, 800
.macro save_clone_context
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
    stp q0, q1, [sp, #256]
    stp q2, q3, [sp, #288]
    stp q4, q5, [sp, #320]
    stp q6, q7, [sp, #352]
    stp q8, q9, [sp, #384]
    stp q10, q11, [sp, #416]
    stp q12, q13, [sp, #448]
    stp q14, q15, [sp, #480]
    stp q16, q17, [sp, #512]
    stp q18, q19, [sp, #544]
    stp q20, q21, [sp, #576]
    stp q22, q23, [sp, #608]
    stp q24, q25, [sp, #640]
    stp q26, q27, [sp, #672]
    stp q28, q29, [sp, #704]
    stp q30, q31, [sp, #736]
    mrs x10, fpcr
    mrs x11, fpsr
    str x10, [sp, #768]
    str x11, [sp, #776]
.endm
.macro restore_vectors
    ldp q0, q1, [sp, #256]
    ldp q2, q3, [sp, #288]
    ldp q4, q5, [sp, #320]
    ldp q6, q7, [sp, #352]
    ldp q8, q9, [sp, #384]
    ldp q10, q11, [sp, #416]
    ldp q12, q13, [sp, #448]
    ldp q14, q15, [sp, #480]
    ldp q16, q17, [sp, #512]
    ldp q18, q19, [sp, #544]
    ldp q20, q21, [sp, #576]
    ldp q22, q23, [sp, #608]
    ldp q24, q25, [sp, #640]
    ldp q26, q27, [sp, #672]
    ldp q28, q29, [sp, #704]
    ldp q30, q31, [sp, #736]
    ldr x10, [sp, #768]
    ldr x11, [sp, #776]
    msr fpcr, x10
    msr fpsr, x11
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
/* Return via a stub-local direct branch. That stub restores x16/x17 from
 * the current parent/child stack, so no register is sacrificed to hold PC. */
.macro return_to_clone_stub offset
    restore_vectors
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
    save_clone_context
    /* Save continuation, then repair the two registers used by the stub. */
    sub x1, x16, #(STUB_DATA_OFFSET - STUB_CLONE_RESUME_OFFSET)
    str x1, [sp, #248]
    ldr x10, [sp, #CLONE_CTX]
    ldr x11, [sp, #(CLONE_CTX + 8)]
    stp x10, x11, [sp, #128]
    ldr x0, [sp, #72]           /* original x9 */
    ldr x2, [sp, #0]            /* clone flags */
    bl clone_notify_prepare
    tbnz x0, #63, prepare_failed
    str x0, [sp, #72]           /* carry transaction in x9 across SVC */
    restore_vectors
    restore_gprs
    add sp, sp, #(CLONE_CTX + 32)
    svc #0
    /* Now SP is the parent's original SP or the child's requested new SP. */
    save_clone_context
    mov x1, x0                 /* kernel result */
    mov x0, x9                 /* transaction */
    bl clone_notify_finish
    str x0, [sp, #72]           /* restore original x9 */
    str x1, [sp, #248]          /* stub continuation */
    return_to_clone_stub (CLONE_CTX - 16)
prepare_failed:
    str x0, [sp, #0]
    return_to_clone_stub (CLONE_CTX + 16)
.size clone_entry,.-clone_entry
.section .note.GNU-stack,"",@progbits
