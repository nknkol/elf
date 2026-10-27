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

#include <signal.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
void _start(void)
{
    long notify=call(__NR_inotify_init1,IN_CLOEXEC|IN_NONBLOCK,0,0,0);
    CHECK(notify>=0 && query(3,notify)==1 && call(__NR_fcntl,notify,F_GETFD,0,0)==FD_CLOEXEC);
    CHECK(call(__NR_fcntl,notify,F_GETFL,0,0)&O_NONBLOCK);
    long watch=call(__NR_inotify_add_watch,notify,(long)"fd-data",IN_MODIFY|IN_CLOSE_WRITE,0);
    CHECK(watch>=0);
    long file=call(__NR_openat,AT_FDCWD,(long)"fd-data",O_WRONLY,0);CHECK(file>=0);
    char c='Q';CHECK(call(__NR_write,file,(long)&c,1,0)==1 && call(__NR_close,file,0,0,0)==0);
    union { struct inotify_event align; char bytes[256]; } events;
    long bytes=call(__NR_read,notify,(long)&events,sizeof(events),0);CHECK(bytes>0);
    unsigned seen=0;
    for(long offset=0;offset<bytes;) {
        struct inotify_event *e=(void *)(events.bytes+offset);
        CHECK(e->wd==watch);seen|=e->mask;offset+=sizeof(*e)+e->len;
    }
    CHECK((seen&(IN_MODIFY|IN_CLOSE_WRITE))==(IN_MODIFY|IN_CLOSE_WRITE));
    CHECK(call(__NR_read,notify,(long)&events,sizeof(events),0)==-EAGAIN);
    CHECK(call(__NR_inotify_rm_watch,notify,watch,0,0)==0);
    CHECK(call(__NR_close,notify,0,0,0)==0 && query(1,notify)==-ENOENT);
    notify=call(__NR_inotify_init1,0,0,0,0);CHECK(notify>=0 && query(3,notify)==0);
    CHECK(call(__NR_close,notify,0,0,0)==0);
    CHECK(call(__NR_inotify_init1,0x80000000,0,0,0)==-EINVAL);
    unsigned long mask=(1ul<<(SIGUSR1-1))|(1ul<<(SIGUSR2-1)),old=0;
    CHECK(call(__NR_rt_sigprocmask,SIG_BLOCK,(long)&mask,(long)&old,8)==0);
    mask=1ul<<(SIGUSR1-1);
    long fd=call(__NR_signalfd4,-1,(long)&mask,8,SFD_CLOEXEC|SFD_NONBLOCK);
    CHECK(fd>=0 && query(3,fd)==1 && call(__NR_fcntl,fd,F_GETFD,0,0)==FD_CLOEXEC);
    struct signalfd_siginfo info;
    CHECK(call(__NR_read,fd,(long)&info,sizeof(info),0)==-EAGAIN);
    long pid=call(__NR_getpid,0,0,0,0),tid=call(__NR_gettid,0,0,0,0);
    CHECK(call(__NR_tgkill,pid,tid,SIGUSR1,0)==0);
    CHECK(call(__NR_read,fd,(long)&info,sizeof(info),0)==sizeof(info) && info.ssi_signo==SIGUSR1);
    long generation=query(1,fd),description=query(2,fd),fillers[127];
    for(int i=0;i<127;i++) { fillers[i]=call(__NR_dup,fd,0,0,0);CHECK(fillers[i]>=0); }
    CHECK(query(0,0)==128);
    CHECK(call(__NR_inotify_init1,0,0,0,0)==-ENOSPC);
    CHECK(call(__NR_signalfd4,-1,(long)&mask,8,0)==-ENOSPC);
    CHECK(call(__NR_signalfd4,fd,(long)&mask,4,0)==-EINVAL);
    CHECK(call(__NR_signalfd4,fd,(long)&mask,8,0x80000000)==-EINVAL);
    CHECK(query(0,0)==128 && query(1,fd)==generation && query(3,fd)==1);
    mask=1ul<<(SIGUSR2-1);
    CHECK(call(__NR_signalfd4,fd,(long)&mask,8,0)==fd);
    CHECK(query(0,0)==128 && query(1,fd)==generation && query(2,fd)==description && query(3,fd)==1);
    CHECK(call(__NR_fcntl,fd,F_GETFD,0,0)==FD_CLOEXEC && (call(__NR_fcntl,fd,F_GETFL,0,0)&O_NONBLOCK));
    CHECK(call(__NR_tgkill,pid,tid,SIGUSR2,0)==0);
    CHECK(call(__NR_close,fd,0,0,0)==0);
    CHECK(call(__NR_read,fillers[0],(long)&info,sizeof(info),0)==sizeof(info) && info.ssi_signo==SIGUSR2);
    for(int i=0;i<127;i++)CHECK(call(__NR_close,fillers[i],0,0,0)==0);
    fd=call(__NR_signalfd4,-1,(long)&mask,8,0);CHECK(fd>=0 && query(3,fd)==0);
    CHECK(call(__NR_signalfd4,fd,(long)&mask,8,SFD_CLOEXEC|SFD_NONBLOCK)==fd);
    CHECK(query(3,fd)==0 && call(__NR_fcntl,fd,F_GETFD,0,0)==0);
    CHECK(!(call(__NR_fcntl,fd,F_GETFL,0,0)&O_NONBLOCK));
    CHECK(call(__NR_close,fd,0,0,0)==0);
    CHECK(call(__NR_signalfd4,-1,(long)&mask,4,0)==-EINVAL);
    CHECK(call(__NR_signalfd4,-1,(long)&mask,8,0x80000000)==-EINVAL);
    CHECK(call(__NR_signalfd4,-1,0,8,0)==-EFAULT);
    CHECK(call(__NR_signalfd4,-2,(long)&mask,8,0)==-EBADF);
    CHECK(call(__NR_rt_sigprocmask,SIG_SETMASK,(long)&old,0,8)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD inotify events and signalfd delivery/update/capacity\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
