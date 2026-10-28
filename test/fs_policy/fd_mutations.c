/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
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
static void denied(long ro)
{
    char byte='X';struct iovec io={&byte,1};
    CHECK(C(write,ro,&byte,1,0,0,0)==-EROFS);
    CHECK(C(writev,ro,&io,1,0,0,0)==-EROFS);
    CHECK(C(pwrite64,ro,&byte,1,0,0,0)==-EROFS);
    CHECK(C(pwritev,ro,&io,1,0,0,0)==-EROFS);
    CHECK(C(pwritev2,ro,&io,1,0,0,0)==-EROFS);
    CHECK(C(ftruncate,ro,0,0,0,0,0)==-EROFS);
    CHECK(C(fallocate,ro,0,0,4096,0,0)==-EROFS);
    CHECK(C(fchmod,ro,0600,0,0,0,0)==-EROFS);
    CHECK(C(fchown,ro,-1,-1,0,0,0)==-EROFS);
    CHECK(C(fsetxattr,ro,"user.test","x",1,0,0)==-EROFS);
    CHECK(C(fremovexattr,ro,"user.test",0,0,0,0)==-EROFS);
    CHECK(C(utimensat,ro,0,0,0,0,0)==-EROFS);
    CHECK(C(fchownat,ro,"",-1,-1,AT_EMPTY_PATH,0)==-EROFS);
    CHECK(C(sendfile,ro,-1,0,1,0,0)==-EROFS);
    CHECK(C(copy_file_range,-1,0,ro,0,1,0)==-EROFS);
    CHECK(C(splice,-1,0,ro,0,1,0)==-EROFS);
    CHECK(C(tee,-1,ro,1,0,0,0)==-EROFS);
    CHECK(C(vmsplice,ro,&io,1,0,0,0)==-EROFS);
}
void run(long *stack)
{
    char byte='W';struct iovec io={&byte,1};
    CHECK(C(write,1,&byte,1,0,0,0)==-EACCES);
    if(stack[0]==2) {
        const char *p=(const char *)stack[2];long inherited=0;
        while(*p)inherited=inherited*10+*p++-'0';
        CHECK(C(write,inherited,&byte,1,0,0,0)==-EACCES);
        CHECK(C(ftruncate,inherited,0,0,0,0,0)==-EACCES);
        close_fd(inherited);
        long fresh=open_file("/rw/file",O_RDWR);CHECK(fresh>=0);
        CHECK(C(pwrite64,fresh,"done",4,0,0,0)==4);
        close_fd(fresh);C(exit_group,0,0,0,0,0,0);for(;;){}
    }
    CHECK(open_file("/ro/file",O_WRONLY)==-EROFS);
    int pipefd[2];CHECK(C(pipe2,pipefd,0,0,0,0,0)==0);
    CHECK(C(write,pipefd[1],&byte,1,0,0,0)==-EACCES);
    close_fd(pipefd[0]);close_fd(pipefd[1]);
    long ro=open_file("/ro/file",O_RDONLY),rw=open_file("/rw/file",O_RDWR);
    CHECK(ro>=0 && rw>=0);denied(ro);
    long dup=C(dup,ro,0,0,0,0,0);CHECK(dup>=0);denied(dup);close_fd(dup);
    long denied_root=open_file("/root-file",O_RDONLY);CHECK(denied_root>=0);
    CHECK(C(write,denied_root,&byte,1,0,0,0)==-EACCES);close_fd(denied_root);
    CHECK(C(write,rw,&byte,1,0,0,0)==1);
    CHECK(C(writev,rw,&io,1,0,0,0)==1);
    CHECK(C(pwrite64,rw,&byte,1,2,0,0)==1);
    CHECK(C(pwritev,rw,&io,1,3,0,0)==1);
    CHECK(C(pwritev2,rw,&io,1,4,0,0)==1);
    CHECK(C(ftruncate,rw,4,0,0,0,0)==0);
    CHECK(C(fchmod,rw,0600,0,0,0,0)==0);
    CHECK(C(utimensat,rw,0,0,0,0,0)==0);
    /* Writable output is checked independently of readonly input. */
    CHECK(C(lseek,ro,0,0,0,0,0)==0);
    CHECK(C(lseek,rw,0,0,0,0,0)==0);
    CHECK(C(sendfile,rw,ro,0,4,0,0)==4);
    dup=C(dup,rw,0,0,0,0,0);CHECK(dup>=0);
    CHECK(C(pwrite64,dup,&byte,1,0,0,0)==1);close_fd(dup);
    CHECK(C(chdir,"/ro",0,0,0,0,0)==0);
    CHECK(C(fchownat,AT_FDCWD,"",-1,-1,AT_EMPTY_PATH,0)==-EROFS);
    long child=C(clone,17,0,0,0,0,0);CHECK(child>=0);
    if(child==0) {
        denied(ro);CHECK(C(pwrite64,rw,&byte,1,0,0,0)==1);
        C(exit_group,0,0,0,0,0,0);for(;;){}
    }
    int status=-1;CHECK(C(wait4,child,&status,0,0,0,0)==child && status==0);
    close_fd(ro);
    /* Slot reuse must not retain the closed readonly descriptor's identity. */
    long reused=open_file("/rw/file",O_RDWR);CHECK(reused==ro);
    CHECK(C(pwrite64,reused,&byte,1,0,0,0)==1);close_fd(reused);
    char digits[24],reverse[24];int n=0,k=0;long value=rw;
    do { reverse[n++]='0'+value%10;value/=10; } while(value);
    while(n)digits[k++]=reverse[--n];digits[k]=0;
    const char *args[]={"/probe",digits,0};
    C(execve,args[0],args,0,0,0,0);CHECK(0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
