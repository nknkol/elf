/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include "stub.h"
.text
.global notify_clone
.type notify_clone,%function
notify_clone:
    sub sp, sp, #256
    stp x18, x19, [sp, #0]
    stp x20, x21, [sp, #16]
    stp x22, x23, [sp, #32]
    stp x24, x25, [sp, #48]
    stp x26, x27, [sp, #64]
    stp x28, x29, [sp, #80]
    str x30, [sp, #96]
    stp q8, q9, [sp, #112]
    stp q10, q11, [sp, #144]
    stp q12, q13, [sp, #176]
    stp q14, q15, [sp, #208]
    mrs x9, fpcr
    mrs x10, fpsr
    str x9, [sp, #240]
    str x10, [sp, #248]
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x5, #105
    mov x6, #106
    mov x7, #107
    mov x8, #__NR_clone
    mov x9, #109
    mov x10, #110
    mov x11, #111
    mov x12, #112
    mov x13, #113
    mov x14, #114
    mov x15, #115
    mov x16, #116
    mov x17, #117
    mov x18, #118
    mov x19, #119
    mov x20, sp
    mov x21, x1
    mov x22, #122
    mov x23, #123
    mov x24, #124
    mov x25, #125
    mov x26, #126
    mov x27, #127
    mov x28, #128
    mov x29, #129
    mov x30, #130
    movi v0.16b, #1
    movi v1.16b, #2
    movi v2.16b, #3
    movi v3.16b, #4
    movi v4.16b, #5
    movi v5.16b, #6
    movi v6.16b, #7
    movi v7.16b, #8
    movi v8.16b, #9
    movi v9.16b, #10
    movi v10.16b, #11
    movi v11.16b, #12
    movi v12.16b, #13
    movi v13.16b, #14
    movi v14.16b, #15
    movi v15.16b, #16
    movi v16.16b, #17
    movi v17.16b, #18
    movi v18.16b, #19
    movi v19.16b, #20
    movi v20.16b, #21
    movi v21.16b, #22
    movi v22.16b, #23
    movi v23.16b, #24
    movi v24.16b, #25
    movi v25.16b, #26
    movi v26.16b, #27
    movi v27.16b, #28
    movi v28.16b, #29
    movi v29.16b, #30
    movi v30.16b, #31
    movi v31.16b, #32
    mov x9, #0x400000
    msr fpcr, x9
    mov x9, #1
    msr fpsr, x9
    mov x9, #109
    b test_stub + 72
resume:
    cbz x0, child_sp
    cmp sp, x20
    b.ne failure
    b verify
child_sp:
    cbz x1, inherited_sp
    cmp sp, x1
    b.ne failure
    b verify
inherited_sp:
    cmp sp, x20
    b.ne failure
verify:
    cmp x1, x21
    b.ne failure
    cmp x2, #0
    b.ne failure
    cmp x3, #0
    b.ne failure
    cmp x4, #0
    b.ne failure
    cmp x5, #105
    b.ne failure
    cmp x6, #106
    b.ne failure
    cmp x7, #107
    b.ne failure
    cmp x8, #220
    b.ne failure
    cmp x9, #109
    b.ne failure
    cmp x10, #110
    b.ne failure
    cmp x11, #111
    b.ne failure
    cmp x12, #112
    b.ne failure
    cmp x13, #113
    b.ne failure
    cmp x14, #114
    b.ne failure
    cmp x15, #115
    b.ne failure
    cmp x16, #116
    b.ne failure
    cmp x17, #117
    b.ne failure
    cmp x18, #118
    b.ne failure
    cmp x19, #119
    b.ne failure
    cmp x22, #122
    b.ne failure
    cmp x23, #123
    b.ne failure
    cmp x24, #124
    b.ne failure
    cmp x25, #125
    b.ne failure
    cmp x26, #126
    b.ne failure
    cmp x27, #127
    b.ne failure
    cmp x28, #128
    b.ne failure
    cmp x29, #129
    b.ne failure
    cmp x30, #130
    b.ne failure
    mrs x9, fpcr
    cmp x9, #0x400, lsl #12
    b.ne failure
    mrs x9, fpsr
    cmp x9, #1
    b.ne failure
.macro verify_vector reg, value
    mov x10, #\value
    orr x10, x10, x10, lsl #8
    orr x10, x10, x10, lsl #16
    orr x10, x10, x10, lsl #32
    umov x9, v\reg\().d[0]
    cmp x9, x10
    b.ne failure
    umov x9, v\reg\().d[1]
    cmp x9, x10
    b.ne failure
.endm
    verify_vector 0, 1
    verify_vector 1, 2
    verify_vector 2, 3
    verify_vector 3, 4
    verify_vector 4, 5
    verify_vector 5, 6
    verify_vector 6, 7
    verify_vector 7, 8
    verify_vector 8, 9
    verify_vector 9, 10
    verify_vector 10, 11
    verify_vector 11, 12
    verify_vector 12, 13
    verify_vector 13, 14
    verify_vector 14, 15
    verify_vector 15, 16
    verify_vector 16, 17
    verify_vector 17, 18
    verify_vector 18, 19
    verify_vector 19, 20
    verify_vector 20, 21
    verify_vector 21, 22
    verify_vector 22, 23
    verify_vector 23, 24
    verify_vector 24, 25
    verify_vector 25, 26
    verify_vector 26, 27
    verify_vector 27, 28
    verify_vector 28, 29
    verify_vector 29, 30
    verify_vector 30, 31
    verify_vector 31, 32
    cbz x0, child_done
    ldr x9, [sp, #240]
    ldr x10, [sp, #248]
    msr fpcr, x9
    msr fpsr, x10
    ldp x18, x19, [sp, #0]
    ldp x20, x21, [sp, #16]
    ldp x22, x23, [sp, #32]
    ldp x24, x25, [sp, #48]
    ldp x26, x27, [sp, #64]
    ldp x28, x29, [sp, #80]
    ldr x30, [sp, #96]
    ldp q8, q9, [sp, #112]
    ldp q10, q11, [sp, #144]
    ldp q12, q13, [sp, #176]
    ldp q14, q15, [sp, #208]
    add sp, sp, #256
    ret
child_done:
    mov x0, #42
    mov x8, #__NR_exit
    svc #0
failure:
    mov x0, #99
    mov x8, #__NR_exit_group
    svc #0
.size notify_clone,.-notify_clone

/* Exact clone portion of generated stub layout. Native/loader matrix checks
 * the emitted machine code separately; this fixture observes real callbacks. */
.balign 16
test_stub:
    .space 72
    sub sp, sp, #32
    stp x16, x17, [sp]
    str x30, [sp, #16]
    adr x16, test_data
    ldr x17, [x16]
    add x17, x17, #PAYLOAD_CLONE_ENTRY_OFFSET
    br x17
test_resume:
    bti j
    ldp x16, x17, [sp], #16
    b resume
    .space 48
test_data:
    .xword test_payload
    .xword resume
    .xword 0
test_payload:
    .space PAYLOAD_CLONE_ENTRY_OFFSET
    b clone_entry
.section .note.GNU-stack,"",@progbits
