/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "fd_runtime.h"
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
static void check_accept(void)
{
    long listener=call(__NR_socket,AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,0);
    CHECK(listener>=0);
    /* Let the kernel choose a unique abstract address; no filesystem fixture. */
    struct sockaddr_un address={.sun_family=AF_UNIX};
    CHECK(call(__NR_bind,listener,(long)&address,sizeof(address.sun_family),0)==0);
    unsigned length=sizeof(address);
    CHECK(call(__NR_getsockname,listener,(long)&address,(long)&length,0)==0);
    CHECK(length>sizeof(address.sun_family) && length<=sizeof(address));
    CHECK(call(__NR_listen,listener,4,0,0)==0);
    CHECK(call(__NR_accept,listener,0,0,0)==-EAGAIN && query(0,0)==1);
    CHECK(call(__NR_accept4,listener,0,0,0)==-EAGAIN && query(0,0)==1);
    CHECK(call(__NR_accept4,listener,0,0,0x80000000)==-EINVAL);
    CHECK(call(__NR_accept,-1,0,0,0)==-EBADF);
    for(int mode=0;mode<3;mode++) {
        long client=call(__NR_socket,AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,0);
        CHECK(client>=0);
        CHECK(call(__NR_connect,client,(long)&address,length,0)==0);
        long filler[126];
        if(mode==0) {
            for(int i=0;i<126;i++) { filler[i]=call(__NR_dup,listener,0,0,0);CHECK(filler[i]>=0); }
            CHECK(query(0,0)==128);
            CHECK(call(__NR_accept,listener,0,0,0)==-ENOSPC);
            CHECK(call(__NR_accept4,listener,0,0,SOCK_CLOEXEC)==-ENOSPC);
            CHECK(query(0,0)==128);
            CHECK(call(__NR_close,filler[125],0,0,0)==0);
        }
        struct sockaddr_un peer={0};unsigned peer_length=sizeof(peer);
        long accepted=call(mode==0?__NR_accept:__NR_accept4,listener,
                           (long)&peer,(long)&peer_length,mode==1?SOCK_CLOEXEC|SOCK_NONBLOCK:0);
        CHECK(accepted>=0 && peer.sun_family==AF_UNIX);
        CHECK(query(3,accepted)==(mode==1));
        CHECK(call(__NR_fcntl,accepted,F_GETFD,0,0)==(mode==1?FD_CLOEXEC:0));
        CHECK(!!(call(__NR_fcntl,accepted,F_GETFL,0,0)&O_NONBLOCK)==!!(EXPECT_ACCEPT_NONBLOCK&(1<<mode)));
        CHECK(query(2,accepted)!=query(2,listener));
        if(mode==0) {
            CHECK(query(0,0)==128);
            for(int i=0;i<125;i++)CHECK(call(__NR_close,filler[i],0,0,0)==0);
        }
        char c='A';CHECK(call(__NR_write,client,(long)&c,1,0)==1);
        c=0;CHECK(call(__NR_read,accepted,(long)&c,1,0)==1 && c=='A');
        c='B';CHECK(call(__NR_write,accepted,(long)&c,1,0)==1);
        c=0;CHECK(call(__NR_read,client,(long)&c,1,0)==1 && c=='B');
        CHECK(call(__NR_close,accepted,0,0,0)==0 && query(1,accepted)==-ENOENT);
        CHECK(call(__NR_read,client,(long)&c,1,0)==0);
        CHECK(call(__NR_close,client,0,0,0)==0 && query(0,0)==1);
    }
    CHECK(call(__NR_close,listener,0,0,0)==0 && query(0,0)==0);
}
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
    CHECK(call(__NR_clone,0x111,0,0,0)==-ENOSYS);
    CHECK(call(__NR_execve,(long)"does-not-exist",0,0,0)==-ENOENT);
    CHECK(call(__NR_close_range,0,~0u,0,0)==-ENOSYS);
    CHECK(call(__NR_pipe2,0,0,0,0)==-EFAULT);
    CHECK(call(__NR_close,other,0,0,0)==0 && call(__NR_close,fourth,0,0,0)==0);
    long mem=call(__NR_memfd_create,(long)"fd-runtime",1,0,0);
    CHECK(mem>=0 && query(3,mem)==1);
    CHECK(call(__NR_fcntl,mem,F_GETFD,0,0)==FD_CLOEXEC);
    char payload='M';CHECK(call(__NR_write,mem,(long)&payload,1,0)==1);
    CHECK(call(__NR_lseek,mem,0,0,0)==0);
    payload=0;CHECK(call(__NR_read,mem,(long)&payload,1,0)==1 && payload=='M');
    long alias=call(__NR_dup,mem,0,0,0);
    CHECK(alias>=0 && query(2,alias)==query(2,mem));
    CHECK(call(__NR_close,mem,0,0,0)==0 && query(1,mem)==-ENOENT);
    CHECK(call(__NR_lseek,alias,0,0,0)==0);
    payload=0;CHECK(call(__NR_read,alias,(long)&payload,1,0)==1 && payload=='M');
    CHECK(call(__NR_close,alias,0,0,0)==0);
    long event=call(__NR_eventfd2,0,O_CLOEXEC|O_NONBLOCK,0,0);
    CHECK(event>=0 && query(3,event)==1);
    CHECK(call(__NR_fcntl,event,F_GETFD,0,0)==FD_CLOEXEC);
    unsigned long count=3;
    CHECK(call(__NR_write,event,(long)&count,8,0)==8);
    count=0;CHECK(call(__NR_read,event,(long)&count,8,0)==8 && count==3);
    CHECK(call(__NR_read,event,(long)&count,8,0)==-EAGAIN);
    long epoll=call(__NR_epoll_create1,EPOLL_CLOEXEC,0,0,0);
    CHECK(epoll>=0 && query(3,epoll)==1 && call(__NR_fcntl,epoll,F_GETFD,0,0)==FD_CLOEXEC);
    struct epoll_event interest={.events=EPOLLIN,.data.u64=123},ready={0};
    CHECK(call(__NR_epoll_ctl,epoll,EPOLL_CTL_ADD,event,(long)&interest)==0);
    count=5;CHECK(call(__NR_write,event,(long)&count,8,0)==8);
    CHECK(call(__NR_epoll_pwait,epoll,(long)&ready,1,1000)==1);
    CHECK((ready.events&EPOLLIN) && ready.data.u64==123);
    CHECK(call(__NR_read,event,(long)&count,8,0)==8 && count==5);
    CHECK(call(__NR_epoll_pwait,epoll,(long)&ready,1,0)==0);
    long timer=call(__NR_timerfd_create,CLOCK_MONOTONIC,TFD_CLOEXEC|TFD_NONBLOCK,0,0);
    CHECK(timer>=0 && query(3,timer)==1 && call(__NR_fcntl,timer,F_GETFD,0,0)==FD_CLOEXEC);
    interest.data.u64=456;
    CHECK(call(__NR_epoll_ctl,epoll,EPOLL_CTL_ADD,timer,(long)&interest)==0);
    struct itimerspec spec={.it_value={.tv_sec=0,.tv_nsec=1000000}};
    CHECK(call(__NR_timerfd_settime,timer,0,(long)&spec,0)==0);
    CHECK(call(__NR_epoll_pwait,epoll,(long)&ready,1,1000)==1);
    CHECK((ready.events&EPOLLIN) && ready.data.u64==456);
    count=0;CHECK(call(__NR_read,timer,(long)&count,8,0)==8 && count==1);
    CHECK(call(__NR_close,timer,0,0,0)==0 && query(1,timer)==-ENOENT);
    CHECK(call(__NR_close,event,0,0,0)==0 && query(1,event)==-ENOENT);
    CHECK(call(__NR_epoll_pwait,epoll,(long)&ready,1,0)==0);
    CHECK(call(__NR_close,epoll,0,0,0)==0 && query(1,epoll)==-ENOENT);
    epoll=call(__NR_epoll_create1,0,0,0,0);
    timer=call(__NR_timerfd_create,CLOCK_MONOTONIC,TFD_NONBLOCK,0,0);
    CHECK(epoll>=0 && timer>=0 && query(3,epoll)==0 && query(3,timer)==0);
    CHECK(call(__NR_close,epoll,0,0,0)==0 && call(__NR_close,timer,0,0,0)==0);
    CHECK(call(__NR_epoll_create1,0x80000000,0,0,0)==-EINVAL);
    CHECK(call(__NR_timerfd_create,-1,0,0,0)==-EINVAL);
    /* Also exercise the flags=0 branch, not only CLOEXEC creation. */
    mem=call(__NR_memfd_create,(long)"fd-runtime",0,0,0);
    event=call(__NR_eventfd2,0,O_NONBLOCK,0,0);
    CHECK(mem>=0 && event>=0 && query(3,mem)==0 && query(3,event)==0);
    CHECK(call(__NR_close,mem,0,0,0)==0 && call(__NR_close,event,0,0,0)==0);
    CHECK(call(__NR_memfd_create,(long)"fd-runtime",0x80000000,0,0)==-EINVAL);
    CHECK(call(__NR_eventfd2,0,0x80000000,0,0)==-EINVAL);
    CHECK(query(0,0)==1);
    int ends[2]={-1,-1};
    CHECK(call(__NR_pipe2,(long)ends,O_CLOEXEC|O_NONBLOCK,0,0)==0);
    CHECK(query(0,0)==3 && query(2,ends[0])!=query(2,ends[1]));
    for(int i=0;i<2;i++) {
        CHECK(query(3,ends[i])==1 && call(__NR_fcntl,ends[i],F_GETFD,0,0)==FD_CLOEXEC);
        CHECK(call(__NR_fcntl,ends[i],F_GETFL,0,0)&O_NONBLOCK);
    }
    CHECK(call(__NR_read,ends[0],(long)&c,1,0)==-EAGAIN);
    copy=call(__NR_dup,ends[1],0,0,0);
    CHECK(copy>=0 && query(2,copy)==query(2,ends[1]));
    CHECK(call(__NR_close,ends[1],0,0,0)==0 && query(1,ends[1])==-ENOENT);
    c='P';CHECK(call(__NR_write,copy,(long)&c,1,0)==1);
    c=0;CHECK(call(__NR_read,ends[0],(long)&c,1,0)==1 && c=='P');
    CHECK(call(__NR_close,copy,0,0,0)==0);
    CHECK(call(__NR_read,ends[0],(long)&c,1,0)==0);
    CHECK(call(__NR_close,ends[0],0,0,0)==0 && query(0,0)==1);
    CHECK(call(__NR_pipe2,(long)ends,0,0,0)==0);
    CHECK(query(3,ends[0])==0 && query(3,ends[1])==0);
    CHECK(call(__NR_close,ends[0],0,0,0)==0 && call(__NR_close,ends[1],0,0,0)==0);
    ends[0]=-1;ends[1]=-1;
    CHECK(call(__NR_pipe2,(long)ends,0x80000000,0,0)==-EINVAL);
    CHECK(ends[0]==-1 && ends[1]==-1 && query(0,0)==1);
    long sock=call(__NR_socket,AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,0);
    CHECK(sock>=0 && query(3,sock)==1 && call(__NR_fcntl,sock,F_GETFD,0,0)==FD_CLOEXEC);
    CHECK(call(__NR_fcntl,sock,F_GETFL,0,0)&O_NONBLOCK);
    CHECK(call(__NR_close,sock,0,0,0)==0 && query(1,sock)==-ENOENT);
    sock=call(__NR_socket,AF_UNIX,SOCK_STREAM,0,0);
    CHECK(sock>=0 && query(3,sock)==0);
    CHECK(call(__NR_close,sock,0,0,0)==0);
    CHECK(call(__NR_socketpair,AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,(long)ends)==0);
    CHECK(query(0,0)==3 && query(2,ends[0])!=query(2,ends[1]));
    for(int i=0;i<2;i++) {
        CHECK(query(3,ends[i])==1 && call(__NR_fcntl,ends[i],F_GETFD,0,0)==FD_CLOEXEC);
        CHECK(call(__NR_fcntl,ends[i],F_GETFL,0,0)&O_NONBLOCK);
        CHECK(call(__NR_read,ends[i],(long)&c,1,0)==-EAGAIN);
        c='S';CHECK(call(__NR_write,ends[i],(long)&c,1,0)==1);
        c=0;CHECK(call(__NR_read,ends[1-i],(long)&c,1,0)==1 && c=='S');
    }
    copy=call(__NR_dup,ends[1],0,0,0);
    CHECK(copy>=0 && query(2,copy)==query(2,ends[1]));
    CHECK(call(__NR_close,ends[1],0,0,0)==0 && query(1,ends[1])==-ENOENT);
    c='D';CHECK(call(__NR_write,copy,(long)&c,1,0)==1);
    c=0;CHECK(call(__NR_read,ends[0],(long)&c,1,0)==1 && c=='D');
    CHECK(call(__NR_close,copy,0,0,0)==0);
    CHECK(call(__NR_read,ends[0],(long)&c,1,0)==0);
    CHECK(call(__NR_close,ends[0],0,0,0)==0 && query(1,ends[0])==-ENOENT);
    CHECK(call(__NR_socketpair,AF_UNIX,SOCK_STREAM,0,(long)ends)==0);
    CHECK(query(3,ends[0])==0 && query(3,ends[1])==0);
    CHECK(call(__NR_close,ends[0],0,0,0)==0 && call(__NR_close,ends[1],0,0,0)==0);
    CHECK(call(__NR_socketpair,AF_UNIX,SOCK_STREAM,0,0)==-EFAULT);
    ends[0]=-1;ends[1]=-1;
    CHECK(call(__NR_socketpair,AF_UNIX,15,0,(long)ends)==-EINVAL);
    CHECK(call(__NR_socket,AF_UNIX,SOCK_STREAM|0x80000000,0,0)==-EINVAL);
    CHECK(query(0,0)==1 && ends[0]==-1 && ends[1]==-1);
    long fds[127];
    for(int i=0;i<126;i++) { fds[i]=call(__NR_dup,fd,0,0,0);CHECK(fds[i]>=0); }
    CHECK(call(__NR_pipe2,(long)ends,0,0,0)==-ENOSPC);
    CHECK(call(__NR_socketpair,AF_UNIX,SOCK_STREAM,0,(long)ends)==-ENOSPC);
    CHECK(ends[0]==-1 && ends[1]==-1 && query(0,0)==127);
    CHECK(call(__NR_close,fds[125],0,0,0)==0 && query(0,0)==126);
    CHECK(call(__NR_pipe2,(long)ends,0,0,0)==0 && query(0,0)==128);
    CHECK(query(1,ends[0])>0 && query(1,ends[1])>0);
    CHECK(call(__NR_close,ends[0],0,0,0)==0 && call(__NR_close,ends[1],0,0,0)==0);
    CHECK(call(__NR_socketpair,AF_UNIX,SOCK_STREAM,0,(long)ends)==0 && query(0,0)==128);
    CHECK(query(1,ends[0])>0 && query(1,ends[1])>0);
    CHECK(call(__NR_close,ends[0],0,0,0)==0 && call(__NR_close,ends[1],0,0,0)==0);
    fds[125]=call(__NR_dup,fd,0,0,0);CHECK(fds[125]>=0);
    for(int i=126;i<127;i++) { fds[i]=call(__NR_dup,fd,0,0,0);CHECK(fds[i]>=0); }
    CHECK(query(0,0)==128);
    CHECK(call(__NR_socket,AF_UNIX,SOCK_STREAM,0,0)==-ENOSPC);
    CHECK(call(__NR_socketpair,AF_UNIX,SOCK_STREAM,0,(long)ends)==-ENOSPC);
    CHECK(call(__NR_pipe2,(long)ends,0,0,0)==-ENOSPC);
    CHECK(call(__NR_dup,fd,0,0,0)==-ENOSPC && query(0,0)==128);
    CHECK(call(__NR_memfd_create,(long)"no-room",0,0,0)==-ENOSPC);
    CHECK(call(__NR_eventfd2,0,0,0,0)==-ENOSPC && query(0,0)==128);
    CHECK(call(__NR_epoll_create1,0,0,0,0)==-ENOSPC);
    CHECK(call(__NR_timerfd_create,CLOCK_MONOTONIC,0,0,0)==-ENOSPC);
    for(int i=0;i<127;i++)CHECK(call(__NR_close,fds[i],0,0,0)==0);
    CHECK(call(__NR_close,fd,0,0,0)==0 && query(0,0)==0);
    check_accept();
    static const char ok[]="PASS: runtime FD open/dup/fcntl/close/memfd/eventfd/epoll/timerfd/pipe2/socket/socketpair/accept/accept4, lifecycle rejection and capacity\n";
    call(__NR_write,1,(long)ok,sizeof(ok)-1,0);
    call(__NR_exit_group,0,0,0,0);for(;;){}
}
