/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "fd_experiment.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }

#include <asm/ioctls.h>
void run(long *sp)
{
    CHECK(sp[0]==2);char **av=(void *)(sp+1);int fd=0;
    for(char *p=av[1];*p;p++)fd=fd*10+*p-'0';
    CHECK(query(0,0)==1 && query(1,fd)==1 && query(2,fd)==1);
    /* Exhausted assignment serial must not prevent non-allocating updates. */
    CHECK(call(__NR_fcntl,fd,F_SETFD,FD_CLOEXEC,0)==0 && query(3,fd)==1);
    CHECK(call(__NR_ioctl,fd,FIONCLEX,0,0)==0 && query(3,fd)==0);
    CHECK(call(__NR_ioctl,fd,FIOCLEX,0,0)==0 && query(3,fd)==1);
    CHECK(call(__NR_fcntl,fd,F_GETFD,0,0)==FD_CLOEXEC);
    CHECK(query(1,fd)==1 && query(2,fd)==1);
    CHECK(call(__NR_dup,fd,0,0,0)==-EOVERFLOW);
    CHECK(call(__NR_memfd_create,(long)"no-wrap",0,0,0)==-EOVERFLOW);
    CHECK(call(__NR_close,fd,0,0,0)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD restored serial exhaustion permits flag updates and close\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
