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

static long beneath(long fd,const char *path,unsigned long flags,unsigned long resolve)
{
    unsigned long how[3]={flags,0,resolve};
    return call(437,fd,(long)path,(long)how,sizeof(how));
}
void _start(void)
{
    long base=query(0,0);
    long dir=call(__NR_openat,AT_FDCWD,(long)".",O_PATH|O_DIRECTORY,0);CHECK(dir>=0);
    unsigned long flags=O_PATH|O_NOFOLLOW|O_CLOEXEC;
    long fd=beneath(dir,"fd-data",flags,8);CHECK(fd>=0);
    CHECK(query(0,0)==base+2 && query(3,fd)==1);
    CHECK(call(__NR_close,fd,0,0,0)==0);
    fd=beneath(AT_FDCWD,"fd-data",O_PATH|O_NOFOLLOW,8);CHECK(fd>=0 && query(3,fd)==0);
    CHECK(call(__NR_close,fd,0,0,0)==0);
    CHECK(beneath(dir,"beneath-mount",flags|O_DIRECTORY,8)==-EOPNOTSUPP);
    CHECK(beneath(dir,"..",flags,8)==-EXDEV);
    CHECK(beneath(dir,"/etc",flags,8)==-EXDEV);
    CHECK(beneath(dir,"../fd-data",flags,8)==-EOPNOTSUPP);
    CHECK(beneath(dir,"./fd-data",flags,8)==-EOPNOTSUPP);
    CHECK(beneath(dir,"",flags,8)==-ENOENT);
    CHECK(beneath(dir,"fd-data",flags,0)==-EOPNOTSUPP);
    CHECK(beneath(dir,"fd-data",O_PATH,8)==-EOPNOTSUPP);
    CHECK(beneath(dir,"fd-data",O_RDONLY,8)==-EOPNOTSUPP);
    CHECK(beneath(dir,"fd-data",flags|O_DIRECTORY,8)==-ENOTDIR);
    CHECK(beneath(dir,"beneath-missing",flags,8)==-ENOENT);
    CHECK(call(__NR_symlinkat,(long)"/",dir,(long)"beneath-link",0)==0);
    fd=beneath(dir,"beneath-link",flags,8);CHECK(fd>=0);
    char value[8];CHECK(call(__NR_readlinkat,fd,(long)"",(long)value,sizeof(value))==1 && value[0]=='/');
    CHECK(call(__NR_close,fd,0,0,0)==0);
    CHECK(beneath(dir,"beneath-link",flags|O_DIRECTORY,8)==-ENOTDIR);
    CHECK(call(__NR_unlinkat,dir,(long)"beneath-link",0,0)==0);
    CHECK(query(0,0)==base+1);
    CHECK(call(__NR_close,dir,0,0,0)==0 && query(0,0)==base);
    static const char pass[]="PASS: runtime FD restricted openat2 beneath anchors, escapes, symlinks and FD accounting\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
