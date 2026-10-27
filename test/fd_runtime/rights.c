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
void _start(void)
{
    int pair[2];CHECK(call(__NR_socketpair,AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,(long)pair)==0);
    long source=call(__NR_memfd_create,(long)"rights",0,0,0);CHECK(source>=0);
    char data='Q';CHECK(call(__NR_write,source,(long)&data,1,0)==1);
    union ancillary buffer={0};struct iovec io={&data,1};
    struct msghdr m={.msg_iov=&io,.msg_iovlen=1,.msg_control=buffer.data,.msg_controllen=sizeof(buffer)};
    CHECK(call(__NR_recvmsg,pair[1],0,0,0)==-EFAULT);
    CHECK(call(__NR_recvmsg,pair[1],(long)&m,0,0)==-EAGAIN && query(0,0)==3);
    send_rights(pair[0],source);
    for(int mode=0;mode<4;mode++) {
        if(mode==3)send_rights(pair[0],source);
        m.msg_controllen=sizeof(buffer);m.msg_flags=0;
        long flags=mode<2?MSG_PEEK:MSG_CMSG_CLOEXEC;
        CHECK(call(__NR_recvmsg,pair[1],(long)&m,flags,0)==1 && data=='R');
        if(mode<3 && !(EXPECT_PEEK_RIGHTS&(1<<mode))) {
            CHECK(m.msg_controllen==0 && query(0,0)==3);continue;
        }
        struct cmsghdr *h=(void *)buffer.data;
        CHECK(h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS && h->cmsg_len==CMSG_LEN(8));
        int *fds=(void *)CMSG_DATA(h);
        CHECK(query(0,0)==5 && fds[0]!=fds[1]);
        for(int i=0;i<2;i++) {
            CHECK(query(1,fds[i])>0 && query(2,fds[i])==0 && query(3,fds[i])==(mode>=2));
            CHECK(call(__NR_fcntl,fds[i],F_GETFD,0,0)==(mode>=2?FD_CLOEXEC:0));
            CHECK(call(__NR_lseek,fds[i],0,0,0)==0);
            data=0;CHECK(call(__NR_read,fds[i],(long)&data,1,0)==1 && data=='Q');
            CHECK(call(__NR_close,fds[i],0,0,0)==0 && query(1,fds[i])==-ENOENT);
        }
    }
    for(int mode=0;mode<2;mode++) {
        send_rights(pair[0],source);
        m.msg_controllen=mode?0:CMSG_LEN(sizeof(int));
        CHECK(call(__NR_recvmsg,pair[1],(long)&m,0,0)==1 && (m.msg_flags&MSG_CTRUNC));
        CHECK(query(0,0)==(mode?3:4));
        if(!mode) {
            int fd=*(int *)CMSG_DATA((struct cmsghdr *)buffer.data);
            CHECK(query(1,fd)>0 && call(__NR_close,fd,0,0,0)==0);
        }
    }
    send_rights(pair[0],source);
    long filler[125];for(int i=0;i<125;i++) { filler[i]=call(__NR_dup,source,0,0,0);CHECK(filler[i]>=0); }
    m.msg_controllen=sizeof(buffer);
    CHECK(call(__NR_recvmsg,pair[1],(long)&m,0,0)==-ENOSPC && query(0,0)==128);
    CHECK(call(__NR_close,filler[124],0,0,0)==0);
    CHECK(call(__NR_recvmsg,pair[1],(long)&m,0,0)==-ENOSPC && query(0,0)==127);
    CHECK(call(__NR_close,filler[123],0,0,0)==0);
    CHECK(call(__NR_recvmsg,pair[1],(long)&m,0,0)==1 && query(0,0)==128);
    int *fds=(void *)CMSG_DATA((struct cmsghdr *)buffer.data);
    CHECK(call(__NR_close,fds[0],0,0,0)==0 && call(__NR_close,fds[1],0,0,0)==0);
    for(int i=0;i<123;i++)CHECK(call(__NR_close,filler[i],0,0,0)==0);
    /* Read-only output control buffer: receipt must roll back installed FDs. */
    long page=call(__NR_mmap,0,4096,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS);CHECK(page>0);
    long next=call(__NR_dup,source,0,0,0);CHECK(next>=0 && call(__NR_close,next,0,0,0)==0);
    send_rights(pair[0],source);m.msg_control=(void *)page;m.msg_controllen=sizeof(buffer);
    CHECK(call(__NR_recvmsg,pair[1],(long)&m,0,0)==-EFAULT && query(0,0)==3);
    long after=call(__NR_dup,source,0,0,0);CHECK(after==next);
    CHECK(call(__NR_close,after,0,0,0)==0 && call(__NR_munmap,page,4096,0,0)==0);
    /* Header fields can also be read-only after a successful kernel receive. */
    page=call(__NR_mmap,0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS);CHECK(page>0);
    m.msg_control=buffer.data;m.msg_controllen=sizeof(buffer);
    *(struct msghdr *)page=m;
    CHECK(call(__NR_mprotect,page,4096,PROT_READ,0)==0);
    send_rights(pair[0],source);
    CHECK(call(__NR_recvmsg,pair[1],page,0,0)==-EFAULT && query(0,0)==3);
    after=call(__NR_dup,source,0,0,0);CHECK(after==next);
    CHECK(call(__NR_close,after,0,0,0)==0 && call(__NR_munmap,page,4096,0,0)==0);
    /* No-control data receive needs no record slots even when the table is full. */
    for(int i=0;i<125;i++) { filler[i]=call(__NR_dup,source,0,0,0);CHECK(filler[i]>=0); }
    data='N';CHECK(call(__NR_write,pair[0],(long)&data,1,0)==1);
    m.msg_control=0;m.msg_controllen=0;
    CHECK(call(__NR_recvmsg,pair[1],(long)&m,0,0)==1 && data=='N' && query(0,0)==128);
    for(int i=0;i<125;i++)CHECK(call(__NR_close,filler[i],0,0,0)==0);
    CHECK(call(__NR_close,source,0,0,0)==0);
    CHECK(call(__NR_close,pair[0],0,0,0)==0 && call(__NR_close,pair[1],0,0,0)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD SCM_RIGHTS receive, peek, truncation, capacity and EFAULT rollback\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
