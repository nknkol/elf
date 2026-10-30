/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "fd_runtime.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }

void run(long *sp)
{
    char **av=(void *)(sp+1);long error=EINVAL;
    if(sp[0]==2) { error=0;for(char *p=av[1];*p;p++)error=error*10+*p-'0'; }
    CHECK(query(0,0)==-error);
    CHECK(call(__NR_openat,AT_FDCWD,(long)"fd-data",O_RDONLY,0)==-error);
    CHECK(query(0,0)==-error);
    call(__NR_exit_group,0,0,0,0);for(;;){}
}

__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
