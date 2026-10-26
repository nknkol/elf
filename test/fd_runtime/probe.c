/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "fd_experiment.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");
    return x0;
}
static void fail(int line)
{ call(__NR_exit_group,line,0,0,0);for(;;){} }
#define CHECK(x) do { if(!(x))fail(__LINE__); } while(0)
static long query(int type,int fd)
{ return call(__NR_prctl,PR_ELF_FD_QUERY,type,fd,0); }
void _start(void)
{
    CHECK(query(0,0)==0);
    long fd=call(__NR_openat,AT_FDCWD,(long)"fd-data",O_RDONLY|O_CLOEXEC,0);
    CHECK(fd>=0 && query(0,0)==1 && query(3,fd)==1);
    char c=0;CHECK(call(__NR_read,fd,(long)&c,1,0)==1 && c=='Q');
    long gen=query(1,fd),desc=query(2,fd);CHECK(gen>0 && desc>0);
    long copy=call(__NR_dup,fd,0,0,0);
    CHECK(copy>=0 && query(1,copy)!=gen && query(2,copy)==desc && query(3,copy)==0);
    long other=call(__NR_openat,AT_FDCWD,(long)"fd-data",O_RDONLY,0);
    CHECK(other>=0 && query(2,other)!=desc);
    CHECK(call(__NR_dup3,fd,other,O_CLOEXEC,0)==other);
    CHECK(query(2,other)==desc && query(3,other)==1);
    CHECK(call(__NR_fcntl,other,F_SETFD,0,0)==0 && query(3,other)==0);
    long fourth=call(__NR_fcntl,fd,F_DUPFD_CLOEXEC,0,0);
    CHECK(fourth>=0 && query(2,fourth)==desc && query(3,fourth)==1);
    CHECK(call(__NR_openat,AT_FDCWD,(long)"does-not-exist",O_RDONLY,0)==-ENOENT);
    CHECK(query(0,0)==4);
    CHECK(call(__NR_close,copy,0,0,0)==0 && query(1,copy)==-ENOENT);
    CHECK(call(__NR_fcntl,copy,F_GETFD,0,0)==-EBADF);
    CHECK(call(__NR_close,copy,0,0,0)==-EBADF && query(0,0)==3);
    CHECK(call(__NR_clone,17,0,0,0)==-ENOSYS);
    CHECK(call(__NR_execve,(long)"does-not-exist",0,0,0)==-ENOSYS);
    CHECK(call(__NR_close_range,0,~0u,0,0)==-ENOSYS);
    CHECK(call(__NR_pipe2,0,0,0,0)==-ENOSYS);
    CHECK(call(__NR_close,other,0,0,0)==0 && call(__NR_close,fourth,0,0,0)==0);
    long fds[127];
    for(int i=0;i<127;i++) { fds[i]=call(__NR_dup,fd,0,0,0);CHECK(fds[i]>=0); }
    CHECK(query(0,0)==128);
    CHECK(call(__NR_dup,fd,0,0,0)==-ENOSPC && query(0,0)==128);
    for(int i=0;i<127;i++)CHECK(call(__NR_close,fds[i],0,0,0)==0);
    CHECK(call(__NR_close,fd,0,0,0)==0 && query(0,0)==0);
    static const char ok[]="PASS: runtime FD open/dup/fcntl/close, lifecycle rejection and capacity\n";
    call(__NR_write,1,(long)ok,sizeof(ok)-1,0);
    call(__NR_exit_group,0,0,0,0);for(;;){}
}
