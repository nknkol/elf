/* SPDX-License-Identifier: GPL-2.0-or-later */
/* A vfork child on a small stack, as glibc's posix_spawn (about 36 KiB with
 * a guard page) and CPython's child (getdents64 over /proc/self/fd before
 * exec): the intercepted calls must fit. Freestanding, raw SVC only. */
#include <asm/unistd.h>
#define STACK (36 * 1024)
#define PAGE 4096
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static const char *target;
static char *const empty[]={0};
/* Runs on the small stack; never returns. */
__attribute__((noinline,used)) void child(void)
{
    char buf[512];
    long fd=sc(__NR_openat,-100,(long)"/proc/self/fd",0x14000 /* O_DIRECTORY|O_RDONLY */,0,0,0);
    if(fd>=0) { sc(__NR_getdents64,fd,(long)buf,sizeof(buf),0,0,0);sc(__NR_close,fd,0,0,0,0,0); }
    char *argv[]={(char *)target,0};
    sc(__NR_execve,(long)target,(long)argv,(long)empty,0,0,0);
    sc(__NR_exit,99,0,0,0,0,0);
}
/* clone(CLONE_VM|CLONE_VFORK|SIGCHLD, stack): the child switches to the
 * new stack inside the svc and calls child(); the parent returns the pid. */
static long spawn(void *top)
{
    register long x8 __asm__("x8")=__NR_clone;
    register long x0 __asm__("x0")=0x4111;
    register long x1 __asm__("x1")=(long)top;
    register long x2 __asm__("x2")=0,x3 __asm__("x3")=0,x4 __asm__("x4")=0;
    __asm__ volatile("svc #0\n cbnz x0, 1f\n bl child\n1:"
                     :"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4):"memory","cc","x30");
    return x0;
}
static void out(const char *s){long n=0;while(s[n])n++;sc(__NR_write,1,(long)s,n,0,0,0);}
void run(long *sp)
{
    target=(const char *)sp[2];
    char *base=(char *)sc(__NR_mmap,0,STACK+PAGE,3,0x22,-1,0);
    sc(__NR_mprotect,(long)base,PAGE,0,0,0,0); /* Guard page below the stack. */
    for(int i=0;i<3;i++) {
        long pid=spawn(base+PAGE+STACK);
        int status=-1;
        if(pid>0)sc(__NR_wait4,pid,(long)&status,0,0,0,0);
        out(status==0 ? "child=0\n" : "child=bad\n");
    }
    sc(__NR_exit_group,0,0,0,0,0,0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
