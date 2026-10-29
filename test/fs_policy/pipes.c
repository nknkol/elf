/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/socket.h>
static long call(long n,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define C(n,a,b,c,d,e,f) call(__NR_##n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define CHECK(x) do { if(!(x)) { C(exit_group,__LINE__,0,0,0,0,0);for(;;){} } } while(0)
static long open_file(const char *path,int flags)
{ return C(openat,AT_FDCWD,path,flags,0600,0,0); }
static void close_fd(long fd) { CHECK(C(close,fd,0,0,0,0,0)==0); }

static void finish(void) { C(exit_group,0,0,0,0,0,0);for(;;){} }
static void byte_read(int fd,char expected)
{ char c=0;CHECK(C(read,fd,&c,1,0,0,0)==1 && c==expected); }
void run(long *stack)
{
    if(stack[0]==2) {
        const char *p=(const char *)stack[2];long inherited=0;
        while(*p)inherited=inherited*10+*p++-'0';
        CHECK(C(write,inherited,"X",1,0,0,0)==-EACCES);close_fd(inherited);
        int fresh[2];CHECK(C(pipe2,fresh,0,0,0,0,0)==0);
        CHECK(C(write,fresh[1],"N",1,0,0,0)==1);byte_read(fresh[0],'N');
        close_fd(fresh[0]);close_fd(fresh[1]);
        CHECK(C(write,1,"PIPE-OK\n",8,0,0,0)==8);finish();
    }
    int pipefd[2];CHECK(C(pipe2,pipefd,0,0,0,0,0)==0);
    CHECK(C(write,pipefd[0],"X",1,0,0,0)==-EACCES);
    CHECK(C(write,pipefd[1],"A",1,0,0,0)==1);byte_read(pipefd[0],'A');
    struct iovec io={(void *)"B",1};CHECK(C(writev,pipefd[1],&io,1,0,0,0)==1);byte_read(pipefd[0],'B');
    CHECK(C(ftruncate,pipefd[1],0,0,0,0,0)==-EACCES);
    CHECK(C(fchmod,pipefd[1],0600,0,0,0,0)==-EACCES);
    CHECK(C(mmap,0,4096,PROT_READ,MAP_SHARED,pipefd[1],0)==-EACCES);
    int sockets[2];CHECK(C(socketpair,AF_UNIX,SOCK_STREAM,0,sockets,0,0)==0);
    CHECK(C(write,sockets[0],"X",1,0,0,0)==-EACCES);
    close_fd(sockets[0]);close_fd(sockets[1]);
    long duplicate=C(fcntl,pipefd[1],F_DUPFD_CLOEXEC,0,0,0,0);CHECK(duplicate>=0);
    CHECK(C(fcntl,duplicate,F_SETFD,0,0,0,0)==0);
    close_fd(pipefd[1]);long ro=open_file("/ro/file",O_RDONLY);CHECK(ro==pipefd[1]);
    CHECK(C(write,ro,"X",1,0,0,0)==-EROFS);
    CHECK(C(write,duplicate,"D",1,0,0,0)==1);byte_read(pipefd[0],'D');
    long overwritten=C(dup,duplicate,0,0,0,0,0);CHECK(overwritten>=0);
    CHECK(C(dup3,ro,overwritten,0,0,0,0)==overwritten);
    CHECK(C(write,overwritten,"X",1,0,0,0)==-EROFS);close_fd(overwritten);
    CHECK(C(sendfile,duplicate,ro,0,1,0,0)==1);byte_read(pipefd[0],'s');
    int other[2];CHECK(C(pipe2,other,0,0,0,0,0)==0);
    CHECK(C(write,duplicate,"T",1,0,0,0)==1);
    CHECK(C(tee,pipefd[0],other[1],1,0,0,0)==1);byte_read(other[0],'T');
    CHECK(C(splice,pipefd[0],0,other[1],0,1,0)==1);byte_read(other[0],'T');
    CHECK(C(vmsplice,other[1],&io,1,0,0,0)==1);byte_read(other[0],'B');
    close_fd(other[0]);close_fd(other[1]);
    const char *missing[]={"/missing-program",0};
    CHECK(C(execve,missing[0],missing,0,0,0,0)==-ENOENT);
    int invalid[2]={-1,-1};CHECK(C(pipe2,invalid,0x40000000,0,0,0,0)==-EINVAL);
    CHECK(C(write,duplicate,"E",1,0,0,0)==1);byte_read(pipefd[0],'E');
    long child=C(clone,17,0,0,0,0,0);CHECK(child>=0);
    if(child==0) { CHECK(C(write,duplicate,"F",1,0,0,0)==1);finish(); }
    int status=-1;CHECK(C(wait4,child,&status,0,0,0,0)==child && status==0);byte_read(pipefd[0],'F');
    close_fd(ro);close_fd(pipefd[0]);
    char digits[24],reverse[24];int n=0,k=0;long value=duplicate;
    do { reverse[n++]='0'+value%10;value/=10; } while(value);
    while(n)digits[k++]=reverse[--n];digits[k]=0;
    const char *args[]={"/probe",digits,0};C(execve,args[0],args,0,0,0,0);CHECK(0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
