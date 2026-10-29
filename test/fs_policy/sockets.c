/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
static long call(long n,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define C(n,a,b,c,d,e,f) call(__NR_##n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define CHECK(x) do { if(!(x)) { C(exit_group,__LINE__,0,0,0,0,0);for(;;){} } } while(0)
static long length(const char *s) { long n=0;while(s[n])n++;return n; }
static long address(struct sockaddr_un *a,const char *path)
{
    unsigned char *bytes=(unsigned char *)a;
    for(unsigned i=0;i<sizeof(*a);i++)bytes[i]=0;
    a->sun_family=AF_UNIX;
    long n=length(path);
    for(long i=0;i<n;i++)a->sun_path[i]=path[i];
    return (long)__builtin_offsetof(struct sockaddr_un,sun_path)+n+1;
}
static long sock(int type) { long fd=C(socket,AF_UNIX,type|SOCK_CLOEXEC,0,0,0,0);CHECK(fd>=0);return fd; }
static long bind_to(long fd,const char *path) { struct sockaddr_un a;long n=address(&a,path);return C(bind,fd,&a,n,0,0,0); }
static long connect_to(long fd,const char *path) { struct sockaddr_un a;long n=address(&a,path);return C(connect,fd,&a,n,0,0,0); }
static void exchange(long client,long server)
{
    char byte=0;
    CHECK(C(sendto,client,"k",1,0,0,0)==1);
    CHECK(C(recvfrom,server,&byte,1,0,0,0)==1 && byte=='k');
}
static void stream(const char *path)
{
    long server=sock(SOCK_STREAM);CHECK(bind_to(server,path)==0);
    CHECK(C(listen,server,4,0,0,0,0)==0);
    long client=sock(SOCK_STREAM);CHECK(connect_to(client,path)==0);
    long accepted=C(accept4,server,0,0,SOCK_CLOEXEC,0,0);CHECK(accepted>=0);
    exchange(client,accepted);
    C(close,accepted,0,0,0,0,0);C(close,client,0,0,0,0,0);C(close,server,0,0,0,0,0);
}
void run(long *stack)
{
    CHECK(stack[0]>=4);
    const char *mode=(const char *)stack[2],*longpath=(const char *)stack[3],*hostpath=(const char *)stack[4];
    int guard=mode[0]=='g';
    /* Guest names are translated into the view, including a host path longer
     * than sun_path (reached through its parent directory FD). */
    stream("/w/s1");
    stream(longpath);
    CHECK(C(chdir,"/w",0,0,0,0,0)==0);
    stream("s2");
    /* connect follows a guest symlink to a listening socket. */
    long target=sock(SOCK_STREAM);CHECK(bind_to(target,"/w/t")==0);
    CHECK(C(listen,target,1,0,0,0,0)==0);
    long client=sock(SOCK_STREAM);
    CHECK(connect_to(client,"/w/link")==0);C(close,client,0,0,0,0,0);C(close,target,0,0,0,0,0);
    CHECK(C(chdir,"/",0,0,0,0,0)==0);
    /* Datagram destinations through sendto and sendmsg. */
    long receiver=sock(SOCK_DGRAM);CHECK(bind_to(receiver,"/w/d")==0);
    long sender=sock(SOCK_DGRAM);
    struct sockaddr_un a;long n=address(&a,"/w/d");char byte=0;
    CHECK(C(sendto,sender,"x",1,0,&a,n)==1);
    CHECK(C(recvfrom,receiver,&byte,1,0,0,0)==1 && byte=='x');
    struct iovec io={(void *)"y",1};
    struct { void *name;int namelen;struct iovec *iov;unsigned long iovlen;void *control;
             unsigned long controllen;unsigned flags; } message={&a,(int)n,&io,1,0,0,0};
    CHECK(C(sendmsg,sender,&message,0,0,0,0)==1);
    CHECK(C(recvfrom,receiver,&byte,1,0,0,0)==1 && byte=='y');
    /* Abstract names never touch the filesystem. */
    long abstract=sock(SOCK_STREAM);
    n=address(&a,"_elf-socket-test");a.sun_path[0]=0;
    CHECK(C(bind,abstract,&a,n-1,0,0,0)==0);C(close,abstract,0,0,0,0,0);
    long probe=sock(SOCK_STREAM);
    if(!guard) {
        /* Without a policy the denied-in-guard root is simply the view. */
        CHECK(connect_to(probe,"/hostsvc.sock")==0);
        C(exit_group,0,0,0,0,0,0);for(;;){}
    }
    CHECK(bind_to(sock(SOCK_STREAM),"/r/s")==-EROFS);
    CHECK(bind_to(sock(SOCK_STREAM),"/denied.sock")==-EACCES);
    CHECK(connect_to(probe,"/hostsvc.sock")==-EACCES);
    /* The host spelling is a guest path inside the denied root, not the host. */
    CHECK(connect_to(probe,hostpath)==-EACCES);
    n=address(&a,"/hostdgram.sock");
    CHECK(C(sendto,sender,"z",1,0,&a,n)==-EACCES);
    message.namelen=(int)n;
    CHECK(C(sendmsg,sender,&message,0,0,0,0)==-EACCES);
    n=address(&a,"/w/d");
    struct { typeof(message) header;unsigned len; } many={message,0};
    many.header.namelen=(int)n;
    CHECK(C(sendmmsg,sender,&many,1,0,0,0)==-EOPNOTSUPP);
    C(exit_group,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
