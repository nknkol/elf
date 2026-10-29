/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <asm/ioctls.h>
#include <asm/termbits.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <errno.h>
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long ctl(long fd,unsigned request,void *arg)
{ return call(__NR_ioctl,fd,request,(long)arg,0); }
static long openfile(const char *p)
{ long fd=call(__NR_openat,AT_FDCWD,(long)p,O_RDWR,0);CHECK(fd>=0);return fd; }
static void blocked(long fd,long error)
{
    CHECK(ctl(fd,FS_IOC_SETFLAGS,0)==error);
    CHECK(ctl(fd,FS_IOC_SETVERSION,0)==error);
    CHECK(ctl(fd,FS_IOC_FSSETXATTR,0)==error);
}
static void unsupported(long fd)
{
    CHECK(ctl(fd,FICLONE,0)==-EOPNOTSUPP);
    CHECK(ctl(fd,FICLONERANGE,0)==-EOPNOTSUPP);
    CHECK(ctl(fd,FIDEDUPERANGE,0)==-EOPNOTSUPP);
    CHECK(ctl(fd,TIOCSTI,0)==-EOPNOTSUPP);
    CHECK(ctl(fd,_IOR('z',99,long),0)==-EOPNOTSUPP);
    CHECK(ctl(fd,_IOW('z',99,long),0)==-EOPNOTSUPP);
    CHECK(ctl(fd,TCSETS,0)==-EOPNOTSUPP);
}
void run(long *stack)
{
    const char *mode=(const char *)stack[2];
    if(mode[0]=='t') {
        struct termios term;unsigned short winsize[4];
        CHECK(ctl(1,TCGETS,&term)==0);
        CHECK(ctl(1,TIOCGWINSZ,winsize)==0);
        unsupported(1);blocked(1,-EACCES);
        call(__NR_exit_group,0,0,0,0);for(;;){}
    }
    long fd;
    if(mode[0]=='n')fd=openfile((const char *)stack[3]);
    else {
        fd=openfile("/rw/file");
#ifdef GUARDED
        long ro=call(__NR_openat,AT_FDCWD,(long)"/ro/file",O_RDONLY,0);CHECK(ro>=0);
        long deny=call(__NR_openat,AT_FDCWD,(long)"/deny/file",O_RDONLY,0);CHECK(deny>=0);
        blocked(ro,-EROFS);blocked(deny,-EACCES);
        long copy=call(__NR_dup,ro,0,0,0);CHECK(copy>=0);blocked(copy,-EROFS);
        CHECK(call(__NR_close,copy,0,0,0)==0);
        CHECK(call(__NR_dup3,fd,ro,0,0)==ro);
        unsupported(fd);unsupported(ro);unsupported(deny);unsupported(-1);
        CHECK(ctl(fd,TIOCGPTPEER,0)==-ENOSYS);
        CHECK(ctl(fd,TCGETS,0)==-EOPNOTSUPP);
        int pipefd[2];CHECK(call(__NR_pipe2,(long)pipefd,0,0,0)==0);
        blocked(pipefd[1],-EACCES);
        CHECK(ctl(pipefd[0],FS_IOC_GETFLAGS,0)==-EOPNOTSUPP);
        int available=-1;
        CHECK(ctl(pipefd[0],FIONREAD,&available)==0 && available==0);
        CHECK(ctl(pipefd[1],FIONBIO,&(int){1})==0);
        CHECK(call(__NR_fcntl,pipefd[1],F_GETFL,0,0)&O_NONBLOCK);
        CHECK(ctl(pipefd[1],FIOCLEX,0)==0);
        CHECK(call(__NR_fcntl,pipefd[1],F_GETFD,0,0)==FD_CLOEXEC);
        CHECK(ctl(pipefd[1],FIONCLEX,0)==0);
        CHECK(call(__NR_fcntl,pipefd[1],F_GETFD,0,0)==0);
        CHECK(ctl(fd,FS_IOC_SETFLAGS,0)==ctl(ro,FS_IOC_SETFLAGS,0));
#endif
    }
    /* Compare to native, including a reversible NODUMP change on a private
     * fixture. Never introduce immutable/append-only flags. */
    long results[8],flags=0;
    results[0]=ctl(fd,FS_IOC_GETFLAGS,&flags);
    results[1]=results[0]==0?ctl(fd,FS_IOC_SETFLAGS,&flags):results[0];
    results[2]=ctl(fd,FS_IOC_SETFLAGS,0);
    results[3]=ctl(fd,FS_IOC_SETVERSION,0);
    results[4]=ctl(fd,FS_IOC_FSSETXATTR,0);
    results[5]=ctl(fd,FIONBIO,&(int){1});
    results[6]=results[7]=results[0];
    if(results[0]==0) {
        long changed=flags^FS_NODUMP_FL, observed=0;
        results[6]=ctl(fd,FS_IOC_SETFLAGS,&changed);
        if(results[6]==0) {
            CHECK(ctl(fd,FS_IOC_GETFLAGS,&observed)==0);
            CHECK((observed&FS_NODUMP_FL)==(changed&FS_NODUMP_FL));
            results[7]=ctl(fd,FS_IOC_SETFLAGS,&flags);
            CHECK(results[7]==0);
        } else results[7]=results[6];
    }
    CHECK(call(__NR_write,1,(long)results,sizeof(results),0)==sizeof(results));
    call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\n mov x0,sp\n bl run\n");
