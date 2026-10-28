/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Independently built targets identify which backing ELF was executed. */
void _start(void) {
    char marker=MARK;
    register long x0 __asm__("x0")=1,x1 __asm__("x1")=(long)&marker,x2 __asm__("x2")=1,x8 __asm__("x8")=64;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x8):"memory","cc");
    x0=0;x8=94;__asm__ volatile("svc #0"::"r"(x0),"r"(x8):"memory","cc");for(;;){}
}
