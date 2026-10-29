/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/mman.h>
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
void run(long *stack)
{
    CHECK(stack[0]>=2);const char *mode=(const char *)stack[2];
    if(mode[0]=='d' || mode[0]=='f') {
        CHECK(C(write,1,"X",1,0,0,0)==-EACCES);finish();
    }
    if(mode[0]=='b') { CHECK(C(write,1,"ok\n",3,0,0,0)==3);finish(); }
    if(mode[0]=='c') {
        CHECK(stack[0]==3);const char *p=(const char *)stack[3];long inherited=0;
        while(*p)inherited=inherited*10+*p++-'0';
        CHECK(C(write,1,"C",1,0,0,0)==1);
        /* Restored aliases do not inherit freshly revalidated stdio grants. */
        CHECK(C(write,inherited,"X",1,0,0,0)==-EACCES);close_fd(inherited);
        long ro=open_file("/ro/file",O_RDONLY);CHECK(ro>2);
        CHECK(C(dup3,ro,1,0,0,0,0)==1);close_fd(ro);
        CHECK(C(write,1,"X",1,0,0,0)==-EROFS);
        const char *args[]={"/probe","file",0};C(execve,args[0],args,0,0,0,0);CHECK(0);
    }
    char byte=0;CHECK(C(read,0,&byte,1,0,0,0)==1 && byte=='R');
    CHECK(C(write,1,"A",1,0,0,0)==1);
    struct iovec io={(void *)"B",1};CHECK(C(writev,1,&io,1,0,0,0)==1);
    CHECK(C(write,2,"\nSTDIO-E\n",9,0,0,0)==9);
    long copy=C(dup,1,0,0,0,0,0);CHECK(copy>2);
    close_fd(1);long ro=open_file("/ro/file",O_RDONLY);CHECK(ro==1);
    CHECK(C(write,1,"X",1,0,0,0)==-EROFS);
    CHECK(C(write,copy,"D",1,0,0,0)==1);
    CHECK(C(dup3,copy,1,0,0,0,0)==1);
    CHECK(C(dup3,copy,64,0,0,0,0)==64);
    CHECK(C(write,64,"Q",1,0,0,0)==1);close_fd(64);
    CHECK(C(ftruncate,copy,0,0,0,0,0)==-EACCES);
    CHECK(C(fchmod,copy,0600,0,0,0,0)==-EACCES);
    CHECK(C(mmap,0,4096,PROT_READ,MAP_SHARED,copy,0)==-EACCES);
    int pipefd[2];CHECK(C(pipe2,pipefd,0,0,0,0,0)==0);
    CHECK(C(write,pipefd[1],"X",1,0,0,0)==-EACCES);
    close_fd(pipefd[0]);close_fd(pipefd[1]);
    long child=C(clone,17,0,0,0,0,0);CHECK(child>=0);
    if(child==0) { CHECK(C(write,copy,"F",1,0,0,0)==1);finish(); }
    int status=-1;CHECK(C(wait4,child,&status,0,0,0,0)==child && status==0);
    char digits[24],reverse[24];int n=0,k=0;long value=copy;
    do { reverse[n++]='0'+value%10;value/=10; } while(value);
    while(n)digits[k++]=reverse[--n];digits[k]=0;
    const char *args[]={"/probe","child",digits,0};C(execve,args[0],args,0,0,0,0);CHECK(0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
