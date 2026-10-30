/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include "fd_runtime.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long decision(long mount,long operation)
{ return call(__NR_prctl,PR_ELF_FD_QUERY,6,mount,operation); }
void run(long *stack)
{
#ifdef NO_POLICY
    CHECK(decision(0,0)==-ENODATA);
#else
    CHECK(decision(0,0)==-EACCES);
    CHECK(decision(1,0)==0);
    CHECK(decision(1,1)==-EROFS);
    CHECK(decision(2,1)==0);
    CHECK(decision(3,0)==-EACCES);
    CHECK(decision(-1,0)==-EACCES);
    CHECK(decision(1,9)==-EINVAL);
#endif
    if(stack[0]<3) {
        const char *args[]={"/probe","again",stack[0]==2?"twice":0,0};
        call(__NR_execve,(long)args[0],(long)args,0,0);CHECK(0);
    }
    static const char pass[]="PASS: policy observation survived two exec calls\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);
    call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
