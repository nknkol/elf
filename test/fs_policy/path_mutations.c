/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "fd_experiment.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)

static long open_path(int fd,const char *path,long flags)
{ return call(__NR_openat,fd,(long)path,flags,0600); }
static void closefd(long fd)
{ CHECK(fd>=0);CHECK(call(__NR_close,fd,0,0,0)==0); }
void run(long *stack)
{
#ifdef OBSERVE_ONLY
    closefd(open_path(AT_FDCWD,"/ro/file",O_WRONLY));
#else
    if(stack[0]==3) {
        const char *digits=(const char *)stack[3];long inherited=0;
        while(*digits)inherited=inherited*10+*digits++-'0';
        /* Exec-imported origins stay unknown, even under a writable mapping. */
        CHECK(open_path(inherited,"file",O_WRONLY)==-EACCES);
        closefd(inherited);
    }
    CHECK(open_path(AT_FDCWD,"unknown",O_CREAT|O_WRONLY)==-EACCES);
    CHECK(open_path(AT_FDCWD,"/denied",O_CREAT|O_WRONLY)==-EACCES);
    CHECK(open_path(AT_FDCWD,"/ro/file",O_WRONLY)==-EROFS);
    CHECK(open_path(AT_FDCWD,"/ro/file",O_RDWR)==-EROFS);
    CHECK(open_path(AT_FDCWD,"/ro/file",O_RDONLY|O_TRUNC)==-EROFS);
    CHECK(open_path(AT_FDCWD,"/ro/new",O_CREAT|O_RDONLY)==-EROFS);
    CHECK(open_path(AT_FDCWD,"/ro",O_TMPFILE|O_RDWR)==-EROFS);
    closefd(open_path(AT_FDCWD,"/ro/file",O_RDONLY));
    closefd(open_path(AT_FDCWD,"/ro/file",O_PATH|O_TRUNC));
    CHECK(call(__NR_mkdirat,AT_FDCWD,(long)"/ro/newdir",0700,0)==-EROFS);
    CHECK(call(__NR_mknodat,AT_FDCWD,(long)"/ro/node",010600,0)==-EROFS);
    CHECK(call(__NR_unlinkat,AT_FDCWD,(long)"/ro/file",0,0)==-EROFS);
    CHECK(call(__NR_symlinkat,(long)"opaque",AT_FDCWD,(long)"/ro/link",0)==-EROFS);
    CHECK(call(__NR_fchmodat,AT_FDCWD,(long)"/ro/file",0600,0)==-EROFS);
    CHECK(call(__NR_fchownat,AT_FDCWD,(long)"/ro/file",-1,-1)==-EROFS);
    CHECK(call(__NR_utimensat,AT_FDCWD,(long)"/ro/file",0,0)==-EROFS);
    CHECK(call(__NR_truncate,(long)"/ro/file",0,0,0)==-EROFS);
    CHECK(call(__NR_renameat,AT_FDCWD,(long)"/ro/file",AT_FDCWD,(long)"/rw/moved")==-EROFS);
    CHECK(call(__NR_renameat,AT_FDCWD,(long)"/rw/file",AT_FDCWD,(long)"/ro/moved")==-EROFS);
    CHECK(call(__NR_renameat2,AT_FDCWD,(long)"/ro/file",AT_FDCWD,(long)"/rw/moved")==-EROFS);
    CHECK(call(__NR_linkat,AT_FDCWD,(long)"/ro/file",AT_FDCWD,(long)"/rw/link")==-EROFS);
    CHECK(call(__NR_linkat,AT_FDCWD,(long)"/rw/file",AT_FDCWD,(long)"/ro/link")==-EROFS);
    CHECK(call(__NR_renameat,AT_FDCWD,(long)"/rw/file",AT_FDCWD,(long)"/ro/nested/file")==-EXDEV);
    CHECK(call(__NR_linkat,AT_FDCWD,(long)"/rw/file",AT_FDCWD,(long)"/ro/nested/file")==-EXDEV);
    /* Final symlink destination, not original prefix, decides permission. */
    CHECK(open_path(AT_FDCWD,"/rw/to_ro",O_WRONLY)==-EROFS);
    closefd(open_path(AT_FDCWD,"/ro/to_rw",O_WRONLY));
    closefd(open_path(AT_FDCWD,"/ro/nested/file",O_WRONLY));
    long ro=open_path(AT_FDCWD,"/ro",O_PATH|O_DIRECTORY);
    long rw=open_path(AT_FDCWD,"/rw",O_PATH|O_DIRECTORY);
    CHECK(ro>=0 && rw>=0);
    CHECK(open_path(ro,"file",O_WRONLY)==-EROFS);
    closefd(open_path(rw,"file",O_WRONLY));
    CHECK(call(__NR_renameat,rw,(long)"file",ro,(long)"moved")==-EROFS);
    CHECK(call(__NR_chdir,(long)"/ro",0,0,0)==0);
    CHECK(open_path(AT_FDCWD,"file",O_WRONLY)==-EROFS);
    CHECK(call(__NR_chdir,(long)"/rw",0,0,0)==0);
    closefd(open_path(AT_FDCWD,"file",O_WRONLY));
    closefd(open_path(rw,"created",O_CREAT|O_WRONLY|O_EXCL));
    CHECK(call(__NR_truncate,(long)"/rw/created",4,0,0)==0);
    CHECK(call(__NR_fchmodat,rw,(long)"created",0600,0)==0);
    CHECK(call(__NR_symlinkat,(long)"/ro/file",rw,(long)"newlink",0)==0);
    CHECK(call(__NR_unlinkat,rw,(long)"newlink",0,0)==0);
    CHECK(open_path(rw,"to_ro",O_CREAT|O_EXCL|O_WRONLY)==-EEXIST);
    CHECK(call(__NR_renameat,rw,(long)"created",rw,(long)"renamed")==0);
    CHECK(call(__NR_unlinkat,rw,(long)"renamed",0,0)==0);
    CHECK(call(__NR_mkdirat,rw,(long)"directory",0700,0)==0);
    CHECK(call(__NR_unlinkat,rw,(long)"directory",AT_REMOVEDIR,0)==0);
    closefd(ro);
    if(stack[0]!=1)closefd(rw);
#endif
    if(stack[0]==1) {
#ifdef OBSERVE_ONLY
        const char *args[]={"/probe","again",0};
#else
        char digits[24], reverse[24];int n=0,k=0;long value=rw;
        do { reverse[n++]='0'+value%10;value/=10; } while(value);
        while(n)digits[k++]=reverse[--n];digits[k]=0;
        const char *args[]={"/probe","again",digits,0};
#endif
        call(__NR_execve,(long)args[0],(long)args,0,0);CHECK(0);
    }
    static const char pass[]="PASS: path mutation mode and exec\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);
    call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
