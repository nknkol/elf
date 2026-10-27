/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "fd_experiment.h"
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
    /* Independent ABI list; exercise patched SVC dispatch, not policy helpers. */
    const long calls[]={__NR_fanotify_init,__NR_userfaultfd,__NR_perf_event_open,
        __NR_bpf,__NR_mq_open,__NR_open_tree,__NR_fsopen,__NR_fsmount,
        __NR_fspick,__NR_open_by_handle_at,__NR_seccomp,__NR_io_uring_setup,
#ifdef __NR_landlock_create_ruleset
        __NR_landlock_create_ruleset,
#endif
#ifdef __NR_memfd_secret
        __NR_memfd_secret,
#endif
    };
    long fd=call(__NR_memfd_create,(long)"unsupported-control",0,0,0);CHECK(fd>=0);
    long generation=query(1,fd),description=query(2,fd);
    for(unsigned i=0;i<sizeof(calls)/sizeof(calls[0]);i++) {
        CHECK(call(calls[i],0,0,0,0)==-ENOSYS);
        CHECK(call(calls[i],-1,-1,-1,-1)==-ENOSYS);
        CHECK(query(0,0)==1 && query(1,fd)==generation && query(2,fd)==description);
    }
    /* Common supported creators still work after every rejected call. */
    long copy=call(__NR_dup,fd,0,0,0);CHECK(copy>=0 && query(2,copy)==description);
    char c='U';CHECK(call(__NR_write,copy,(long)&c,1,0)==1);
    CHECK(call(__NR_lseek,fd,0,0,0)==0);
    c=0;CHECK(call(__NR_read,fd,(long)&c,1,0)==1 && c=='U');
    CHECK(call(__NR_close,copy,0,0,0)==0 && call(__NR_close,fd,0,0,0)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD unsupported direct creators return ENOSYS without metadata changes\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
