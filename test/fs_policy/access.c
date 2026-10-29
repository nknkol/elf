/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Sandbox development regression: private fixture only, no host privilege
 * escalation or system-sandbox bypass. Validate this tool's own W_OK policy. */
#include <asm/unistd.h>
#include <fcntl.h>
#include <errno.h>
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long accessat(long n,int fd,const char *path,long mode,long flags)
{ return call(n,fd,(long)path,mode,flags); }
void run(long *stack)
{
    const char *kind=(const char *)stack[2];int guarded=kind[0]=='g', full=kind[1]=='f';
    const char *digits=(const char *)stack[3];long inherited=0;
    while(*digits)inherited=inherited*10+*digits++-'0';
    long ro=call(__NR_openat,AT_FDCWD,(long)"/ro/file",O_RDONLY,0);CHECK(ro>=0);
    long rw=call(__NR_openat,AT_FDCWD,(long)"/rw/file",O_RDONLY,0);CHECK(rw>=0);
    long directory=call(__NR_openat,AT_FDCWD,(long)"/ro",O_RDONLY|O_DIRECTORY,0);CHECK(directory>=0);
    long syscalls[]={__NR_faccessat,__NR_faccessat2};
    for(unsigned i=0;i<2;i++) {
        long n=syscalls[i];
        CHECK(accessat(n,directory,"file",2,0)==(guarded?-EROFS:0));
        CHECK(accessat(n,AT_FDCWD,"/ro/file",2,0)==(guarded?-EROFS:0));
        CHECK(accessat(n,AT_FDCWD,"/ro/file",6,0)==(guarded?-EROFS:0));
        CHECK(accessat(n,AT_FDCWD,"/ro/file",(1ul<<32)|2,0)==(guarded?-EROFS:0));
        CHECK(accessat(n,AT_FDCWD,"/ro/file",4,0)==0);
        CHECK(accessat(n,AT_FDCWD,"/ro/file",0,0)==0);
        CHECK(accessat(n,AT_FDCWD,"/ro/file",10,0)==-EINVAL);
        CHECK(accessat(n,AT_FDCWD,"/rw/file",2,0)==0);
        CHECK(accessat(n,AT_FDCWD,"/deny/file",2,0)==(guarded?-EACCES:0));
        CHECK(accessat(n,AT_FDCWD,"/rw/to_ro",2,0)==(guarded?-EROFS:0));
        CHECK(accessat(n,AT_FDCWD,"/ro/to_rw",2,0)==0);
        CHECK(accessat(n,AT_FDCWD,"/ro/nested/file",2,0)==0);
        CHECK(accessat(n,AT_FDCWD,"rw/file",2,0)==(guarded?-EACCES:0));
    }
    CHECK(accessat(__NR_faccessat2,AT_FDCWD,"/ro/to_rw",2,AT_SYMLINK_NOFOLLOW)==(guarded?-EROFS:NATIVE_LINK_W_OK));
    CHECK(accessat(__NR_faccessat2,AT_FDCWD,"/ro/file",2,AT_EACCESS)==(guarded?-EROFS:0));
    CHECK(accessat(__NR_faccessat2,AT_FDCWD,"/ro/file",2,0x40000000)==-EINVAL);
    CHECK(accessat(__NR_faccessat2,ro,"",2,AT_EMPTY_PATH)==(full?-EROFS:NATIVE_EMPTY_W_OK));
    CHECK(accessat(__NR_faccessat2,rw,"",2,AT_EMPTY_PATH)==NATIVE_EMPTY_W_OK);
    CHECK(accessat(__NR_faccessat2,inherited,"",2,AT_EMPTY_PATH)==(full?-EACCES:NATIVE_INHERITED_W_OK));
    CHECK(accessat(__NR_faccessat2,AT_FDCWD,"",2,AT_EMPTY_PATH)==(full?-EACCES:NATIVE_CWD_W_OK));
    CHECK(accessat(__NR_faccessat2,ro,"",2,AT_EMPTY_PATH|0x40000000)==-EINVAL);
    CHECK(accessat(__NR_faccessat2,ro,"",10,AT_EMPTY_PATH)==-EINVAL);
    CHECK(call(__NR_chdir,(long)"/rw",0,0,0)==0);
    CHECK(accessat(__NR_faccessat,AT_FDCWD,"file",2,0)==0);
    CHECK(accessat(__NR_faccessat2,AT_FDCWD,"",2,AT_EMPTY_PATH)==NATIVE_CWD_W_OK);
    CHECK(call(__NR_chdir,(long)"/ro",0,0,0)==0);
    CHECK(accessat(__NR_faccessat,AT_FDCWD,"file",2,0)==(guarded?-EROFS:0));
    CHECK(accessat(__NR_faccessat2,AT_FDCWD,"",2,AT_EMPTY_PATH)==(full?-EROFS:NATIVE_CWD_W_OK));
    call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\n mov x0,sp\n bl run\n");
