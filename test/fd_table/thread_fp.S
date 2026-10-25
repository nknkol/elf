/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host capability probe: native CLONE_THREAD clears child x29 here. */
.text
.global _start
_start:
 mov x0,#0xd00
 movk x0,#1,lsl #16
 adr x1,stack_end
 mov x2,#0
 mov x3,#0
 mov x4,#0
 mov x29,#129
 mov x8,#220
 svc #0
 cbz x0,child
1: mov x8,#124
 svc #0
 b 1b
child:
 cmp x29,#0
 cset x0,ne
 mov x8,#94
 svc #0
.bss
.balign 16
stack:
 .skip 65536
stack_end:

.section .note.GNU-stack,"",@progbits
