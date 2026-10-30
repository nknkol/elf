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

void _start(void) {
    for(int mode=0;mode<7;mode++) {
        long pid=call(__NR_clone,17,0,0,0);CHECK(pid>=0);
        if(pid==0) {
            const char *directory=(mode%2 || mode==6)?"/two":"/one";
            CHECK(call(__NR_chdir,(long)directory,0,0,0)==0);
            const char *args[]={"program",0};
            if(mode==2 || mode==3 || mode==6) {
                long fd=call(__NR_openat,AT_FDCWD,(long)(mode==6?"/one":directory),O_PATH|O_DIRECTORY,0);CHECK(fd>=0);
                call(__NR_execveat,fd,(long)(mode==6?"script":"nested/program"),(long)args,0);
            } else call(__NR_execve,(long)(mode>=4?"/entryscript":"nested/program"),(long)args,0,0);
            CHECK(0);
        }
        int status=-1;CHECK(call(__NR_wait4,pid,(long)&status,0,0)==pid && status==0);
    }
    static const char pass[]="\nPASS: runtime FD exec cwd/dirfd and relative shebang mount views\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
