/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "fd_runtime.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
#if FD_TRACK
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }
#endif

#include <asm/ioctls.h>
void run(long *sp)
{
    CHECK(sp[0]==2);char **av=(void *)(sp+1);int inherited=0;
    for(char *p=av[1];*p;p++) { CHECK(*p>='0' && *p<='9');inherited=inherited*10+*p-'0'; }
    long fd=call(__NR_memfd_create,(long)"ioctl",0,0,0);CHECK(fd>=0);
    long copy=call(__NR_dup,fd,0,0,0);CHECK(copy>=0);
    long generation=query(1,fd),description=query(2,fd);
    CHECK(call(__NR_ioctl,fd,FIOCLEX,0,0)==0 && query(3,fd)==1);
    CHECK(call(__NR_fcntl,fd,F_GETFD,0,0)==FD_CLOEXEC);
    CHECK(query(3,copy)==0 && call(__NR_fcntl,copy,F_GETFD,0,0)==0);
    CHECK(call(__NR_ioctl,fd,FIONCLEX,0,0)==0 && query(3,fd)==0);
    CHECK(query(1,fd)==generation && query(2,fd)==description);
    CHECK(call(__NR_ioctl,-1,FIOCLEX,0,0)==-EBADF && query(0,0)==2);
    CHECK(call(__NR_ioctl,fd,TIOCGPTPEER,O_RDWR,0)==-ENOSYS && query(0,0)==2);
    /* Status-flag ioctl remains a kernel operation, not descriptor metadata. */
    int nonblock=1;CHECK(call(__NR_ioctl,fd,FIONBIO,(long)&nonblock,0)==0);
    CHECK(call(__NR_fcntl,copy,F_GETFL,0,0)&O_NONBLOCK);
    CHECK(query(1,fd)==generation && query(2,fd)==description && query(3,fd)==0);
    long filler[126];
    for(int i=0;i<126;i++) { filler[i]=call(__NR_dup,fd,0,0,0);CHECK(filler[i]>=0); }
    CHECK(query(0,0)==128 && query(1,inherited)==-ENOENT);
    CHECK(call(__NR_ioctl,fd,FIOCLEX,0,0)==0 && query(3,fd)==1);
    CHECK(call(__NR_ioctl,fd,FIONCLEX,0,0)==0 && query(3,fd)==0);
    CHECK(call(__NR_ioctl,inherited,FIOCLEX,0,0)==-ENOSPC);
    CHECK(call(__NR_fcntl,inherited,F_GETFD,0,0)==0 && query(1,inherited)==-ENOENT);
    CHECK(call(__NR_close,filler[125],0,0,0)==0);
    CHECK(call(__NR_ioctl,inherited,FIOCLEX,0,0)==0 && query(0,0)==128);
    CHECK(query(3,inherited)==1 && query(2,inherited)==0 && call(__NR_fcntl,inherited,F_GETFD,0,0)==FD_CLOEXEC);
    CHECK(call(__NR_ioctl,inherited,FIONCLEX,0,0)==0 && query(3,inherited)==0);
    for(int i=0;i<125;i++)CHECK(call(__NR_close,filler[i],0,0,0)==0);
    CHECK(call(__NR_close,fd,0,0,0)==0 && call(__NR_close,copy,0,0,0)==0);
    CHECK(call(__NR_close,inherited,0,0,0)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD ioctl CLOEXEC tracking, inherited FD capacity and peer rejection\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
