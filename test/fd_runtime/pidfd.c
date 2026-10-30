/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "fd_runtime.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }

void _start(void)
{
    long pid=call(__NR_getpid,0,0,0,0);
    long handle=call(__NR_pidfd_open,pid,0,0,0);
    CHECK(handle>=0 && query(3,handle)==1 && call(__NR_fcntl,handle,F_GETFD,0,0)==FD_CLOEXEC);
    long source=call(__NR_memfd_create,(long)"pidfd-import",0,0,0);CHECK(source>=0);
    char bytes[2]={'A','B'};
    CHECK(call(__NR_write,source,(long)bytes,2,0)==2 && call(__NR_lseek,source,0,0,0)==0);
    long imported=call(__NR_pidfd_getfd,handle,source,0,0);
    CHECK(imported>=0 && query(0,0)==3 && query(1,imported)>0 && query(2,imported)==0 && query(3,imported)==1);
    CHECK(call(__NR_fcntl,imported,F_GETFD,0,0)==FD_CLOEXEC);
    char c=0;CHECK(call(__NR_read,imported,(long)&c,1,0)==1 && c=='A');
    /* Shared kernel offset, without asserting a known metadata alias. */
    CHECK(call(__NR_read,source,(long)&c,1,0)==1 && c=='B');
    CHECK(call(__NR_close,source,0,0,0)==0 && query(1,source)==-ENOENT);
    CHECK(call(__NR_lseek,imported,0,0,0)==0);
    CHECK(call(__NR_read,imported,(long)&c,1,0)==1 && c=='A');
    CHECK(call(__NR_pidfd_getfd,-1,imported,0,0)==-EBADF);
    CHECK(call(__NR_pidfd_getfd,handle,-1,0,0)==-EBADF);
    CHECK(call(__NR_pidfd_getfd,handle,imported,1,0)==-EINVAL);
    CHECK(call(__NR_pidfd_open,pid,0x80000000,0,0)==-EINVAL && query(0,0)==2);
    long alias=call(__NR_dup,handle,0,0,0);CHECK(alias>=0 && query(2,alias)==query(2,handle));
    CHECK(call(__NR_close,handle,0,0,0)==0);
    long again=call(__NR_pidfd_getfd,alias,imported,0,0);CHECK(again>=0 && query(2,again)==0);
    CHECK(call(__NR_close,again,0,0,0)==0);
    long filler[126];
    for(int i=0;i<126;i++) { filler[i]=call(__NR_dup,imported,0,0,0);CHECK(filler[i]>=0); }
    CHECK(query(0,0)==128);
    CHECK(call(__NR_pidfd_open,pid,0,0,0)==-ENOSPC);
    CHECK(call(__NR_pidfd_getfd,alias,imported,0,0)==-ENOSPC && query(0,0)==128);
    CHECK(call(__NR_close,filler[125],0,0,0)==0);
    again=call(__NR_pidfd_getfd,alias,imported,0,0);CHECK(again>=0 && query(0,0)==128 && query(3,again)==1);
    CHECK(call(__NR_close,again,0,0,0)==0);
    for(int i=0;i<125;i++)CHECK(call(__NR_close,filler[i],0,0,0)==0);
    CHECK(call(__NR_close,imported,0,0,0)==0 && call(__NR_close,alias,0,0,0)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD pidfd creation/import, shared offset, errors and capacity\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
