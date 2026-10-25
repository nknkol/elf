/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
.text
.global start_clone
.type start_clone,%function
start_clone:
    /* Child has its own stack. Do not return through the parent's C frames.
     * Place the child argument on that stack BEFORE invoking clone. */
    sub x1, x1, #16
    str x2, [x1]
    mov x2, x3                  /* parent_tid */
    mov x4, x3                  /* child_tid */
    mov x3, #0                  /* no CLONE_SETTLS */
    mov x8, #__NR_clone
    svc #0
    cbz x0, child
    ret
child:
    ldr x0, [sp]
    add sp, sp, #16
    bl child_main
    brk #0
.size start_clone,.-start_clone
.section .note.GNU-stack,"",@progbits
