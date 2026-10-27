/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/time.h>
#include "fd_experiment.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }

#include <linux/sched.h>
static char *decimal(char *buffer,long value) {
    char *p=buffer+31;*p=0;do { *--p='0'+value%10;value/=10; } while(value);return p;
}
static long number(const char *p) { long n=0;while(*p)n=n*10+*p++-'0';return n; }
static long fork_call(long flags,int *child_tid)
{
    register long x0 __asm__("x0")=flags,x1 __asm__("x1")=0,x2 __asm__("x2")=0,x3 __asm__("x3")=0;
    register long x4 __asm__("x4")=(long)child_tid,x5 __asm__("x5")=0,x8 __asm__("x8")=__NR_clone;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
void run(long *sp)
{
    char **av=(void *)(sp+1);
    if(sp[0]==4) {
        long fd=number(av[2]);
        CHECK(query(0,0)==1 && query(1,fd)==number(av[3]) && query(3,fd)==0);
        char c=0;CHECK(call(__NR_read,fd,(long)&c,1,0)==1 && c=='F');
        CHECK(call(__NR_close,fd,0,0,0)==0 && query(0,0)==0);
        call(__NR_exit_group,42,0,0,0);for(;;){}
    }
    CHECK(sp[0]==1);
    /* clone notification must initialize metadata even before any slow call. */
    long first=fork_call(17,0);CHECK(first>=0);
    if(!first) {
        CHECK(query(0,0)==0);call(__NR_exit_group,42,0,0,0);for(;;){}
    }
    int first_status=0;
    CHECK(call(__NR_wait4,first,(long)&first_status,0,0)==first && first_status==(42<<8));
    CHECK(query(0,0)==0);
    long fd=call(__NR_memfd_create,(long)"fork",0,0,0);CHECK(fd>=0);
    char c='F';CHECK(call(__NR_write,fd,(long)&c,1,0)==1);
    CHECK(call(__NR_lseek,fd,0,0,0)==0);
    long generation=query(1,fd);
    CHECK(call(__NR_clone,CLONE_VM|17,0,0,0)==-ENOSYS);
    CHECK(call(__NR_clone,CLONE_FILES|17,0,0,0)==-ENOSYS);
    CHECK(call(__NR_clone,CLONE_VFORK|CLONE_VM|CLONE_FILES|17,0,0,0)==-ENOSYS);
    for(int round=0;round<3;round++) {
        int pipe[2];CHECK(call(__NR_pipe2,(long)pipe,0,0,0)==0);
        CHECK(call(__NR_fcntl,fd,F_SETFD,0,0)==0);
        long flags=17;int child_tid=0;
        if(round==1)flags|=CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID;
        /* AArch64 clone's child_tid is x4; private child memory only. */
        long child=fork_call(flags,&child_tid);CHECK(child>=0);
        if(!child) {
            if(round==1)CHECK(child_tid==call(__NR_gettid,0,0,0,0));
            CHECK(query(0,0)==3 && query(1,fd)==generation);
            CHECK(call(__NR_close,pipe[1],0,0,0)==0);
            CHECK(call(__NR_read,pipe[0],(long)&c,1,0)==1 && c=='P');
            CHECK(query(3,fd)==0 && call(__NR_fcntl,fd,F_GETFD,0,0)==0);
            CHECK(call(__NR_close,pipe[0],0,0,0)==0);
            if(round==2) {
                char digits[2][32];char *next[]={av[0],"child",decimal(digits[0],fd),decimal(digits[1],generation),0};
                call(__NR_execve,(long)av[0],(long)next,0,0);CHECK(0);
            }
            CHECK(call(__NR_close,fd,0,0,0)==0 && query(0,0)==0);
            call(__NR_exit_group,42,0,0,0);for(;;){}
        }
        CHECK(call(__NR_close,pipe[0],0,0,0)==0);
        CHECK(call(__NR_fcntl,fd,F_SETFD,FD_CLOEXEC,0)==0);
        c='P';CHECK(call(__NR_write,pipe[1],(long)&c,1,0)==1);
        CHECK(call(__NR_close,pipe[1],0,0,0)==0);
        int status=0;CHECK(call(__NR_wait4,child,(long)&status,0,0)==child && status==(42<<8));
        CHECK(query(0,0)==1 && query(1,fd)==generation && query(3,fd)==1);
        CHECK(call(__NR_fcntl,fd,F_GETFD,0,0)==FD_CLOEXEC);
    }
    /* A child that already owns a private guard must be able to fork again. */
    long branch=fork_call(17,0);CHECK(branch>=0);
    if(!branch) {
        CHECK(query(1,fd)==generation);
        long leaf=fork_call(17,0);CHECK(leaf>=0);
        if(!leaf) {
            CHECK(query(1,fd)==generation);
            CHECK(call(__NR_close,fd,0,0,0)==0);
            call(__NR_exit_group,42,0,0,0);for(;;){}
        }
        int status=0;CHECK(call(__NR_wait4,leaf,(long)&status,0,0)==leaf && status==(42<<8));
        CHECK(query(1,fd)==generation && call(__NR_fcntl,fd,F_GETFD,0,0)==FD_CLOEXEC);
        call(__NR_exit_group,42,0,0,0);for(;;){}
    }
    int branch_status=0;
    CHECK(call(__NR_wait4,branch,(long)&branch_status,0,0)==branch && branch_status==(42<<8));
    /* Successful exec also abandons its old entry frame. Exercise more than
     * the shared pool capacity without changing the parent's CLOEXEC. */
    for(int round=0;round<40;round++) {
        long child=fork_call(17,0);CHECK(child>=0);
        if(!child) {
            CHECK(call(__NR_fcntl,fd,F_SETFD,0,0)==0);
            CHECK(call(__NR_lseek,fd,0,0,0)==0);
            char digits[2][32];char *next[]={av[0],"child",decimal(digits[0],fd),decimal(digits[1],generation),0};
            call(__NR_execve,(long)av[0],(long)next,0,0);CHECK(0);
        }
        int status=0;CHECK(call(__NR_wait4,child,(long)&status,0,0)==child && status==(42<<8));
        CHECK(query(0,0)==1 && query(1,fd)==generation && query(3,fd)==1);
    }
    /* Terminated children must not consume the parent's 32 shared guard slots. */
    for(int round=0;round<40;round++) {
        long child=fork_call(17,0);CHECK(child>=0);
        if(!child) {
            CHECK(query(0,0)==1 && query(1,fd)==generation);
            int pair[2];CHECK(call(__NR_socketpair,AF_UNIX,SOCK_STREAM,0,(long)pair)==0);
            char byte;struct iovec vector={&byte,1};struct msghdr message={0};
            message.msg_iov=&vector;message.msg_iovlen=1;
            struct itimerval timer={{0,0},{0,50000}};
            CHECK(call(__NR_setitimer,ITIMER_REAL,(long)&timer,0,0)==0);
            call(__NR_recvmsg,pair[0],(long)&message,0,0);CHECK(0);
        }
        int status=0;CHECK(call(__NR_wait4,child,(long)&status,0,0)==child && status==14);
        CHECK(query(0,0)==1 && query(1,fd)==generation && query(3,fd)==1);
    }
    CHECK(call(__NR_close,fd,0,0,0)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD private fork, copied flags, child close, nested fork, 40 execs and 40 interrupted children\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
