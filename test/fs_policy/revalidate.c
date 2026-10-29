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

static void finish(void) { C(exit_group,0,0,0,0,0,0);for(;;){} }
void run(long *stack)
{
    CHECK(stack[0]>=2);const char *mode=(const char *)stack[2];long fd=-1;
    if(mode[0]=='s') { fd=open_file("/out/file",O_RDWR);CHECK(fd>=0); }
    else {
        CHECK(stack[0]==3);const char *p=(const char *)stack[3];fd=0;
        while(*p)fd=fd*10+*p++-'0';
        if(mode[0]=='r' || mode[0]=='d') {
            long error=mode[0]=='r'?-EROFS:-EACCES;
            CHECK(C(write,fd,"X",1,0,0,0)==error);
            CHECK(C(ftruncate,fd,0,0,0,0,0)==error);
            CHECK(C(fchmod,fd,0600,0,0,0,0)==error);finish();
        }
        if(mode[0]=='a') { CHECK(C(pwrite64,fd,"END",3,0,0,0)==3);finish(); }
        CHECK(C(write,fd,"OK",2,0,0,0)==2);
        CHECK(C(fchmod,fd,0600,0,0,0,0)==0);
        long alias=C(dup,fd,0,0,0,0,0);CHECK(alias>=0);
        CHECK(C(write,alias,"!",1,0,0,0)==1);close_fd(alias);
        CHECK(C(ftruncate,fd,3,0,0,0,0)==0);
    }
    char digits[24],reverse[24];int n=0,k=0;long value=fd;
    do { reverse[n++]='0'+value%10;value/=10; } while(value);
    while(n)digits[k++]=reverse[--n];digits[k]=0;
    const char *args[]={"/probe",mode[0]=='s'?"write":"again",digits,0};
    C(execve,args[0],args,0,0,0,0);CHECK(0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
