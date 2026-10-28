/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "fd_experiment.h"
#include "fd_table.h"
#include <asm/stat.h>
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }

static void size(long dir,const char *path,long expected) {
    struct stat st;
    CHECK(call(__NR_newfstatat,dir,(long)path,(long)&st,0)==0);
    CHECK(st.st_size==expected);
}
void _start(void) {
    long a=call(__NR_openat,AT_FDCWD,(long)"/one",O_PATH|O_DIRECTORY,0);
    long b=call(__NR_openat,AT_FDCWD,(long)"/two",O_PATH|O_DIRECTORY,0);CHECK(a>=0 && b>=0);
    size(a,"nested/value",2);size(b,"nested/value",4);
    CHECK(call(__NR_chdir,(long)"/one",0,0,0)==0);
    size(AT_FDCWD,"nested/value",2);
    CHECK(call(__NR_faccessat,AT_FDCWD,(long)"nested/value",0,0)==0);
    char link[16];
    CHECK(call(__NR_readlinkat,a,(long)"nested/link",(long)link,sizeof(link))==1 && link[0]=='N');
    CHECK(call(__NR_readlinkat,b,(long)"nested/link",(long)link,sizeof(link))==1 && link[0]=='S');
    CHECK(call(__NR_symlinkat,(long)"literal-target",a,(long)"nested/newlink",0)==0);
    CHECK(call(__NR_readlinkat,AT_FDCWD,(long)"nested/newlink",(long)link,sizeof(link))==14);
    CHECK(call(__NR_mkdirat,a,(long)"nested/made",0700,0)==0);
    CHECK(call(__NR_mkdirat,b,(long)"nested/made",0700,0)==0);
    CHECK(call(__NR_renameat,a,(long)"nested/made",b,(long)"nested/wrong")==-EXDEV);
    CHECK(call(__NR_linkat,a,(long)"nested/value",b,(long)"nested/wronglink")==-EXDEV);
    CHECK(call(__NR_renameat,a,(long)"nested/made",AT_FDCWD,(long)"nested/renamed")==0);
    CHECK(call(__NR_renameat,AT_FDCWD,(long)"nested/renamed",a,(long)"nested/made")==0);
    CHECK(call(__NR_unlinkat,AT_FDCWD,(long)"nested/made",AT_REMOVEDIR,0)==0);
    CHECK(call(__NR_unlinkat,b,(long)"nested/made",AT_REMOVEDIR,0)==0);
    CHECK(call(__NR_truncate,(long)"nested/value",1,0,0)==0);
    size(a,"nested/value",1);size(b,"nested/value",4);
    CHECK(call(__NR_unlinkat,a,(long)"nested/value",0,0)==0);
    struct stat st;CHECK(call(__NR_newfstatat,a,(long)"nested/value",(long)&st,0)==-ENOENT);
    size(b,"nested/value",4);
    CHECK(call(__NR_close,a,0,0,0)==0 && call(__NR_close,b,0,0,0)==0);
    static const char pass[]="PASS: runtime FD path context stat/readlink/mkdir/symlink/rename/link/truncate/unlink views\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
