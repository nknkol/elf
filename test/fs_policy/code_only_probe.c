/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Linked with --no-rosegment: .rodata shares the executable segment. A
 * constant that encodes `svc #0` must survive hooking (only SHF_EXECINSTR
 * sections are scanned), while the real svc below is still hooked. */
#include <asm/unistd.h>
static const volatile unsigned literal[2] = {0xd4000001u, 0xd4000001u};
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static void out(const char *s,long n){if(n<0){n=0;while(s[n])n++;}sc(__NR_write,1,(long)s,n,0,0,0);}
void run(long *sp)
{
    (void)sp;
    out(literal[0]==0xd4000001u && literal[1]==0xd4000001u ? "literal=intact\n" : "literal=patched\n",-1);
    long fd=sc(__NR_openat,-100,(long)"/etc/alpine-release",0,0,0,0);
    char buf[64];long n=fd>=0?sc(__NR_read,fd,(long)buf,sizeof(buf),0,0,0):0;
    out("open=",-1);if(fd<0)out("error\n",-1);else out(buf,n);
    sc(__NR_exit_group,0,0,0,0,0,0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
