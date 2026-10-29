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

static long map(long length,int prot,int flags,int fd)
{ return C(mmap,0,length,prot,flags,fd,0); }
static void mapped(long p) { CHECK((unsigned long)p<(unsigned long)-4095); }
void run(long *stack)
{
    if(stack[0]==2) {
        const char *p=(const char *)stack[2];long fd=0;
        while(*p)fd=fd*10+*p++-'0';
        CHECK(map(PAGE_SIZE,PROT_READ,MAP_SHARED,fd)==-EACCES);
        close_fd(fd);C(exit_group,0,0,0,0,0,0);for(;;){}
    }
    long ro=open_file("/ro/file",O_RDONLY),rw=open_file("/rw/file",O_RDWR);
    CHECK(ro>=0 && rw>=0);
    CHECK(map(PAGE_SIZE,PROT_READ,MAP_SHARED,ro)==-EROFS);
    CHECK(map(PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED,ro)==-EROFS);
    CHECK(map(PAGE_SIZE,PROT_READ,MAP_SHARED_VALIDATE,ro)==-EROFS);
    CHECK(map(PAGE_SIZE,PROT_READ|PROT_EXEC,MAP_SHARED,rw)==-EOPNOTSUPP);
    long denied=open_file("/root-file",O_RDONLY);CHECK(denied>=0);
    CHECK(map(PAGE_SIZE,PROT_READ,MAP_SHARED,denied)==-EACCES);close_fd(denied);
    long priv=map(PAGE_SIZE,PROT_READ,MAP_PRIVATE,ro);mapped(priv);
    CHECK(C(mprotect,priv,PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==0);
    *(volatile char *)priv='P';
    CHECK(C(msync,priv,PAGE_SIZE,MS_SYNC,0,0,0)==0);
    CHECK(C(munmap,priv,PAGE_SIZE,0,0,0,0)==0);
    long shared=map(PAGE_SIZE,PROT_READ,MAP_SHARED,rw);mapped(shared);
    close_fd(rw);
    CHECK(C(mprotect,shared,PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==0);
    *(volatile char *)shared='M';
    CHECK(C(msync,shared,PAGE_SIZE,MS_SYNC,0,0,0)==0);
    CHECK(C(munmap,shared,PAGE_SIZE,0,0,0,0)==0);
    long anon=map(3*PAGE_SIZE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1);mapped(anon);
    CHECK(C(mprotect,anon,3*PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==0);
    *(volatile char *)anon='A';
    CHECK(C(munmap,anon+1,PAGE_SIZE,0,0,0,0)==-EINVAL);
    CHECK(C(mmap,anon+1,PAGE_SIZE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==-EINVAL);
    CHECK(C(mprotect,anon,PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==0);
    CHECK(C(munmap,anon+PAGE_SIZE,PAGE_SIZE,0,0,0,0)==0);
    CHECK(C(mprotect,anon,3*PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==-EACCES);
    CHECK(C(mprotect,anon+2*PAGE_SIZE,PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==0);
    CHECK(C(mmap,anon+PAGE_SIZE,PAGE_SIZE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,-1,0)==anon+PAGE_SIZE);
    CHECK(C(mprotect,anon,3*PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==0);
    long child=C(clone,17,0,0,0,0,0);CHECK(child>=0);
    if(child==0) {
        CHECK(C(mprotect,anon,PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==0);
        *(volatile char *)anon='C';C(exit_group,0,0,0,0,0,0);for(;;){}
    }
    int status=-1;CHECK(C(wait4,child,&status,0,0,0,0)==child && status==0);
    CHECK(*(volatile char *)anon=='A');
    CHECK(C(mremap,anon,3*PAGE_SIZE,3*PAGE_SIZE,0x40000000,0,0)==-EINVAL);
    CHECK(C(mprotect,anon,PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==0);
    CHECK(C(mremap,anon,3*PAGE_SIZE,3*PAGE_SIZE,0,0,0)==anon);
    CHECK(C(mprotect,anon,PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==-EACCES);
    CHECK(C(madvise,anon,PAGE_SIZE,MADV_REMOVE,0,0,0)==-EACCES);
    CHECK(C(munmap,anon,3*PAGE_SIZE,0,0,0,0)==0);
    long stack_page=(long)stack&~(PAGE_SIZE-1);
    CHECK(C(mprotect,stack_page,PAGE_SIZE,PROT_READ|PROT_WRITE,0,0,0)==-EACCES);
    CHECK(C(mprotect,stack_page,PAGE_SIZE,PROT_READ|PROT_EXEC,0,0,0)==-EACCES);
    CHECK(C(pkey_mprotect,stack_page,PAGE_SIZE,PROT_READ,0,0,0)==-ENOSYS);
    close_fd(ro);
    rw=open_file("/rw/file",O_RDWR);CHECK(rw>=0);
    char digits[24],reverse[24];int n=0,k=0;long value=rw;
    do { reverse[n++]='0'+value%10;value/=10; } while(value);
    while(n)digits[k++]=reverse[--n];digits[k]=0;
    const char *args[]={"/probe",digits,0};C(execve,args[0],args,0,0,0,0);CHECK(0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
