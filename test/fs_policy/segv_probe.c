/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Mode h: install a SIGSEGV handler, query it back, then fault; the handler
 * reports and exits 0. Mode d: fault with no handler (dies of SIGSEGV). */
#include <asm/unistd.h>
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static void out(const char *s){long n=0;while(s[n])n++;sc(__NR_write,1,(long)s,n,0,0,0);}
struct k_sigaction { void *handler; unsigned long flags; void *restorer; unsigned long mask; };
static void handler(int sig){(void)sig;out("handled\n");sc(__NR_exit_group,0,0,0,0,0,0);}
void run(long *sp)
{
    char mode=sp[0]>1?((char **)sp)[2][0]:'d';
    if(mode=='h') {
        struct k_sigaction act={(void *)handler,0,0,0},old={0};
        long rc=sc(__NR_rt_sigaction,11,(long)&act,0,8,0,0);
        sc(__NR_rt_sigaction,11,0,(long)&old,8,0,0);
        out(rc==0 && old.handler==(void *)handler ? "installed\n" : "missing\n");
    }
    *(volatile int *)8=1;
    out("survived\n");
    sc(__NR_exit_group,3,0,0,0,0,0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
