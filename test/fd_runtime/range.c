/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "fd_experiment.h"
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
void run(long *sp)
{
    CHECK(sp[0]==2);char **av=(void *)(sp+1);int inherited=0;
    for(char *p=av[1];*p;p++) { CHECK(*p>='0' && *p<='9');inherited=inherited*10+*p-'0'; }
    long fd=call(__NR_memfd_create,(long)"range",0,0,0);CHECK(fd>=0);
    long duplicate=call(__NR_dup,fd,0,0,0);CHECK(duplicate>=0);
    int fds[3]={inherited,fd,duplicate};
#if FD_TRACK
    CHECK(query(0,0)==2 && query(1,inherited)==-ENOENT);
    long generation=query(1,fd),description=query(2,fd);
#endif
    unsigned flags[]={0,4,2,6,8};
    for(unsigned i=0;i<sizeof(flags)/sizeof(flags[0]);i++) {
        CHECK(call(__NR_close_range,0,~0u,flags[i],0)==-ENOSYS);
        for(int j=0;j<3;j++)CHECK(call(__NR_fcntl,fds[j],F_GETFD,0,0)==0);
#if FD_TRACK
        CHECK(query(0,0)==2 && query(1,fd)==generation && query(2,fd)==description && query(3,fd)==0);
#endif
    }
    CHECK(call(__NR_close_range,100,1,0,0)==-ENOSYS);
    /* Caller fallback is explicit: set flags and close known descriptors. */
    for(int j=0;j<3;j++) {
        CHECK(call(__NR_fcntl,fds[j],F_SETFD,FD_CLOEXEC,0)==0);
        CHECK(call(__NR_fcntl,fds[j],F_GETFD,0,0)==FD_CLOEXEC);
#if FD_TRACK
        CHECK(query(3,fds[j])==1);
#endif
    }
    for(int j=0;j<3;j++) {
        CHECK(call(__NR_close,fds[j],0,0,0)==0);
        CHECK(call(__NR_fcntl,fds[j],F_GETFD,0,0)==-EBADF);
#if FD_TRACK
        CHECK(query(1,fds[j])==-ENOENT);
#endif
    }
#if FD_TRACK
    CHECK(query(0,0)==0);
#endif
    static const char pass[]="PASS: runtime FD close_range ENOSYS preserves FDs and supports caller fallback\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
