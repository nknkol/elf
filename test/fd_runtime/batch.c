#define _GNU_SOURCE
#include <time.h>
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
union ancillary { struct cmsghdr align; char data[CMSG_SPACE(2*sizeof(int))]; };
static void send_rights(int socket,int fd)
{
    union ancillary buffer={0};
    struct cmsghdr *h=(void *)buffer.data;
    h->cmsg_len=CMSG_LEN(2*sizeof(int));h->cmsg_level=SOL_SOCKET;h->cmsg_type=SCM_RIGHTS;
    int *fds=(void *)CMSG_DATA(h);fds[0]=fd;fds[1]=fd;
    char c='R';struct iovec io={&c,1};
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=buffer.data,.msg_controllen=sizeof(buffer)};
    CHECK(call(__NR_sendmsg,socket,(long)&m,0,0)==1);
}

static long batch(int fd,struct mmsghdr *messages,unsigned count,long flags,struct timespec *timeout)
{
    register long x0 __asm__("x0")=fd,x1 __asm__("x1")=(long)messages,x2 __asm__("x2")=count,x3 __asm__("x3")=flags;
    register long x4 __asm__("x4")=(long)timeout,x5 __asm__("x5")=0,x8 __asm__("x8")=__NR_recvmmsg;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
static void reset(struct mmsghdr m[2],union ancillary controls[2],struct iovec io[2])
{
    for(int i=0;i<2;i++)m[i]=(struct mmsghdr){.msg_hdr={.msg_iov=&io[i],.msg_iovlen=1,
        .msg_control=controls[i].data,.msg_controllen=sizeof(controls[i])},.msg_len=777};
}
static void close_received(struct mmsghdr *m,int cloexec)
{
    CHECK(m->msg_len==1);
    struct cmsghdr *h=m->msg_hdr.msg_control;
    CHECK(h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS && h->cmsg_len==CMSG_LEN(8));
    int *fds=(void *)CMSG_DATA(h);
    for(int i=0;i<2;i++) {
        CHECK(query(1,fds[i])>0 && query(2,fds[i])==0 && query(3,fds[i])==cloexec);
        CHECK(call(__NR_fcntl,fds[i],F_GETFD,0,0)==(cloexec?FD_CLOEXEC:0));
        CHECK(call(__NR_close,fds[i],0,0,0)==0);
    }
}
void _start(void)
{
    int pair[2];CHECK(call(__NR_socketpair,AF_UNIX,SOCK_DGRAM|SOCK_NONBLOCK,0,(long)pair)==0);
    long source=call(__NR_memfd_create,(long)"batch",0,0,0);CHECK(source>=0);
    union ancillary controls[2];char data[2];struct iovec io[2]={{&data[0],1},{&data[1],1}};
    struct mmsghdr m[2];reset(m,controls,io);
    CHECK(batch(pair[1],0,0,MSG_DONTWAIT,0)==0);
    CHECK(batch(pair[1],m,9,MSG_DONTWAIT,0)==-E2BIG);
    CHECK(batch(pair[1],m,2,MSG_DONTWAIT,0)==-EAGAIN && query(0,0)==3);
    send_rights(pair[0],source);send_rights(pair[0],source);
    CHECK(batch(pair[1],m,2,MSG_DONTWAIT|MSG_CMSG_CLOEXEC,0)==2 && query(0,0)==7);
    CHECK(data[0]=='R' && data[1]=='R');close_received(&m[0],1);close_received(&m[1],1);
    reset(m,controls,io);send_rights(pair[0],source);
    CHECK(batch(pair[1],m,2,MSG_DONTWAIT,0)==1 && m[1].msg_len==777 && query(0,0)==5);
    close_received(&m[0],0);
    /* A blocking socket plus WAITFORONE must not wait for the second message. */
    CHECK(call(__NR_fcntl,pair[1],F_SETFL,0,0)==0);
    reset(m,controls,io);send_rights(pair[0],source);
    CHECK(batch(pair[1],m,2,MSG_WAITFORONE,0)==1 && m[1].msg_len==777);
    close_received(&m[0],0);
    CHECK(call(__NR_fcntl,pair[1],F_SETFL,O_NONBLOCK,0)==0);
    /* Reserve the whole vector before consuming either message. */
    long filler[122];for(int i=0;i<122;i++) { filler[i]=call(__NR_dup,source,0,0,0);CHECK(filler[i]>=0); }
    reset(m,controls,io);send_rights(pair[0],source);send_rights(pair[0],source);
    CHECK(batch(pair[1],m,2,MSG_DONTWAIT,0)==-ENOSPC && query(0,0)==125);
    CHECK(m[0].msg_len==777 && m[1].msg_len==777);
    CHECK(call(__NR_close,filler[121],0,0,0)==0);
    CHECK(batch(pair[1],m,2,MSG_DONTWAIT,0)==2 && query(0,0)==128);
    close_received(&m[0],0);close_received(&m[1],0);
    for(int i=0;i<121;i++)CHECK(call(__NR_close,filler[i],0,0,0)==0);
    /* Failure publishing the second message keeps the first and closes suffix. */
    long page=call(__NR_mmap,0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS);CHECK(page>0);
    *(struct timespec *)page=(struct timespec){0};
    CHECK(call(__NR_mprotect,page,4096,PROT_READ,0)==0);
    long next=call(__NR_dup,source,0,0,0);CHECK(next>=0 && call(__NR_close,next,0,0,0)==0);
    for(int failed=0;failed<2;failed++) {
        reset(m,controls,io);m[failed].msg_hdr.msg_control=(void *)page;
        send_rights(pair[0],source);send_rights(pair[0],source);
        CHECK(batch(pair[1],m,2,MSG_DONTWAIT,0)==(failed?1:-EFAULT));
        CHECK(query(0,0)==(failed?5:3));
        if(failed)close_received(&m[0],0);
        long after=call(__NR_dup,source,0,0,0);CHECK(after==next && call(__NR_close,after,0,0,0)==0);
    }
    /* Timeout input/output is copied safely; no installed FDs lost on EFAULT. */
    reset(m,controls,io);send_rights(pair[0],source);
    CHECK(batch(pair[1],m,1,MSG_DONTWAIT,(void *)1)==-EFAULT);
    struct timespec timeout={.tv_sec=1};
    CHECK(batch(pair[1],m,1,MSG_DONTWAIT,&timeout)==1);close_received(&m[0],0);
    reset(m,controls,io);send_rights(pair[0],source);
    CHECK(batch(pair[1],m,1,MSG_DONTWAIT,(void *)page)==-EFAULT && query(0,0)==3);
    long after=call(__NR_dup,source,0,0,0);CHECK(after==next && call(__NR_close,after,0,0,0)==0);
    CHECK(call(__NR_munmap,page,4096,0,0)==0);
    /* msg_len alone is read-only, after all msghdr fields were published. */
    page=call(__NR_mmap,0,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS);CHECK(page>0);
    reset(m,controls,io);
    struct mmsghdr *edge=(void *)(page+4096-__builtin_offsetof(struct mmsghdr,msg_len));
    *edge=m[0];
    CHECK(call(__NR_mprotect,page+4096,4096,PROT_READ,0)==0);
    send_rights(pair[0],source);
    CHECK(batch(pair[1],edge,1,MSG_DONTWAIT,0)==-EFAULT && query(0,0)==3);
    after=call(__NR_dup,source,0,0,0);CHECK(after==next && call(__NR_close,after,0,0,0)==0);
    CHECK(call(__NR_munmap,page,8192,0,0)==0);
    CHECK(call(__NR_close,source,0,0,0)==0);
    CHECK(call(__NR_close,pair[0],0,0,0)==0 && call(__NR_close,pair[1],0,0,0)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD recvmmsg batch, partial success, capacity, timeout and rollback\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
