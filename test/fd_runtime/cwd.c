/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "fd_experiment.h"
#include "fd_table.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }

static char child_stack[65536] __attribute__((aligned(16)));
static volatile int marker;
static int equal(const char *a,const char *b) { while(*a && *a==*b){a++;b++;}return *a==*b; }
static void cwd(char *buffer) { CHECK(call(__NR_getcwd,(long)buffer,4096,0,0)>0); }
static void value(char expected,long mount,long access) {
    long fd=call(__NR_openat,AT_FDCWD,(long)"value",O_RDONLY,0);CHECK(fd>=0);
    char c=0;CHECK(call(__NR_read,fd,(long)&c,1,0)==1 && c==expected);
#if FD_TRACK
    CHECK(query(4,fd)==mount && query(5,fd)==access);
#endif
    CHECK(call(__NR_close,fd,0,0,0)==0);
}
void child(void) {
#if FD_TRACK
    CHECK(call(__NR_chdir,(long)"/other",0,0,0)==0);
#else
    CHECK(call(__NR_chdir,(long)"../cwd-b",0,0,0)==0);
#endif
    value('B',4,FD_ACCESS_RW);marker=1;
    call(__NR_exit,0,0,0,0);for(;;){}
}
extern long spawn(void *);
void run(long *sp) {
    char before[4096],after[4096];
#if FD_TRACK
    if(sp[0]==2) {
        /* New payload has no trusted cwd handoff; preserve physical cwd only. */
        value('A',0,FD_ACCESS_UNKNOWN);
        static const char pass[]="PASS: runtime FD cwd aliases, chdir/fchdir, fork/vfork and exec reset\n";
        call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
    }
    long unknown=call(__NR_openat,AT_FDCWD,(long)".",O_PATH|O_DIRECTORY,0);CHECK(unknown>=0);
    CHECK(query(5,unknown)==FD_ACCESS_UNKNOWN);
    CHECK(call(__NR_chdir,(long)"/one",0,0,0)==0);
    CHECK(call(__NR_fchdir,unknown,0,0,0)==0);
    long unknown_child=call(__NR_openat,AT_FDCWD,(long)"cwd-a/value",O_RDONLY,0);CHECK(unknown_child>=0);
    CHECK(query(5,unknown_child)==FD_ACCESS_UNKNOWN);
    CHECK(call(__NR_close,unknown_child,0,0,0)==0 && call(__NR_close,unknown,0,0,0)==0);
    CHECK(call(__NR_chdir,(long)"/one",0,0,0)==0);
    cwd(before);CHECK(equal(before,"/one"));value('A',1,FD_ACCESS_RW);
    long fd=call(__NR_openat,AT_FDCWD,(long)"/two",O_PATH|O_DIRECTORY,0);CHECK(fd>=0);
    CHECK(call(__NR_fchdir,fd,0,0,0)==0);cwd(after);CHECK(equal(after,"/two"));value('A',2,FD_ACCESS_RW);
    CHECK(call(__NR_close,fd,0,0,0)==0);
    CHECK(call(__NR_chdir,(long)"/one",0,0,0)==0);
    CHECK(call(__NR_chdir,(long)"nested",0,0,0)==0);cwd(after);CHECK(equal(after,"/one/nested"));value('B',3,FD_ACCESS_RW);
    CHECK(call(__NR_chdir,(long)"..",0,0,0)==0);value('A',1,FD_ACCESS_RW);
    CHECK(call(__NR_chdir,(long)"missing",0,0,0)==-ENOENT);
    CHECK(call(__NR_fchdir,-1,0,0,0)==-EBADF);cwd(after);CHECK(equal(before,after));
    CHECK(call(__NR_getcwd,(long)after,1,0,0)==-ERANGE);value('A',1,FD_ACCESS_RW);
#else
    CHECK(call(__NR_chdir,(long)"cwd-a",0,0,0)==0);cwd(before);
#endif
    long pid=call(__NR_clone,17,0,0,0);CHECK(pid>=0);
    if(pid==0)child();
    int status=-1;CHECK(call(__NR_wait4,pid,(long)&status,0,0)==pid && status==0);
    cwd(after);CHECK(equal(before,after));value('A',1,FD_ACCESS_RW);
    pid=spawn(child_stack+sizeof(child_stack));CHECK(pid>0 && marker==1);
    status=-1;CHECK(call(__NR_wait4,pid,(long)&status,0,0)==pid && status==0);
    cwd(after);CHECK(equal(before,after));value('A',1,FD_ACCESS_RW);
#if FD_TRACK
    const char *bad_args[]={"/missing",0};
    CHECK(call(__NR_execve,(long)bad_args[0],(long)bad_args,0,0)==-ENOENT);
    cwd(after);CHECK(equal(before,after));value('A',1,FD_ACCESS_RW);
    const char *args[]={"/cwd","exec",0};
    call(__NR_execve,(long)args[0],(long)args,0,0);CHECK(0);
#else
    static const char pass[]="PASS: native fork/vfork retain parent cwd\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
#endif
}
__asm__(".global spawn\nspawn:\nstp x29,x30,[sp,#-16]!\nmov x1,x0\nmov x0,#0x4111\nmov x2,xzr\nmov x3,xzr\nmov x4,xzr\nmov x8,#220\nsvc #0\ncbz x0,1f\nldp x29,x30,[sp],#16\nret\n1: bl child\nbrk #0\n.global _start\n_start: mov x0,sp\nbl run\n");
