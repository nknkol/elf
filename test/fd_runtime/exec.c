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

#include <asm/ioctls.h>
static long number(const char *p) { long n=0;while(*p)n=n*10+*p++-'0';return n; }
static char *decimal(char *buffer,long value) {
    char *p=buffer+31;*p=0;do { *--p='0'+value%10;value/=10; } while(value);return p;
}
static void bound_file(void) {
    long f=call(__NR_openat,AT_FDCWD,(long)"/bound/value",O_RDONLY,0);CHECK(f>=0);
    char c=0;CHECK(call(__NR_read,f,(long)&c,1,0)==1 && c=='V');CHECK(call(__NR_close,f,0,0,0)==0);
}
void run(long *sp)
{
    char **av=(void *)(sp+1);
    if(sp[0]==1) {
        CHECK(query(0,0)==0);bound_file();
        long fd=call(__NR_memfd_create,(long)"exec-state",0,0,0);CHECK(fd>=0);
        char value='X';CHECK(call(__NR_write,fd,(long)&value,1,0)==1 && call(__NR_lseek,fd,0,0,0)==0);
        long copy=call(__NR_dup,fd,0,0,0);CHECK(copy>=0);
        long drop=call(__NR_memfd_create,(long)"drop",1,0,0);CHECK(drop>=0);
        long ioctl_drop=call(__NR_dup,fd,0,0,0);CHECK(ioctl_drop>=0);
        CHECK(call(__NR_ioctl,ioctl_drop,FIOCLEX,0,0)==0);
        char digits[5][32];
        char *next[]={av[0],"1",decimal(digits[0],fd),decimal(digits[1],copy),
            decimal(digits[2],query(1,fd)),decimal(digits[3],query(1,copy)),decimal(digits[4],query(2,fd)),0};
        /* Hide only the runner's private loader copy: kernel exec fails AFTER
         * snapshot creation. The parent table and both CLOEXEC FDs survive. */
        long slot=call(__NR_dup,fd,0,0,0);CHECK(slot>=0 && call(__NR_close,slot,0,0,0)==0);
        CHECK(call(__NR_renameat,AT_FDCWD,(long)"exec-loader",AT_FDCWD,(long)"hidden-loader")==0);
        CHECK(call(__NR_execve,(long)av[0],(long)next,0,0)==-ENOENT);
        CHECK(query(0,0)==4 && query(3,drop)==1 && query(3,ioctl_drop)==1);
        CHECK(call(__NR_fcntl,drop,F_GETFD,0,0)==FD_CLOEXEC);
        long retry=call(__NR_dup,fd,0,0,0);CHECK(retry==slot && call(__NR_close,retry,0,0,0)==0);
        CHECK(call(__NR_renameat,AT_FDCWD,(long)"hidden-loader",AT_FDCWD,(long)"exec-loader")==0);
        call(__NR_execve,(long)av[0],(long)next,0,0);CHECK(0);
    }
    CHECK(sp[0]==7);
    long fd=number(av[2]),copy=number(av[3]);
    CHECK(query(0,0)==2 && query(1,fd)==number(av[4]) && query(1,copy)==number(av[5]));
    CHECK(query(2,fd)==number(av[6]) && query(2,copy)==number(av[6]));
    CHECK(query(3,fd)==0 && query(3,copy)==0);
    bound_file();
    if(av[1][0]=='1') {
        av[1]="2";
        call(__NR_execveat,AT_FDCWD,(long)av[0],(long)av,0);CHECK(0);
    }
    CHECK(av[1][0]=='2');
    char value=0;CHECK(call(__NR_read,copy,(long)&value,1,0)==1 && value=='X');
    CHECK(call(__NR_lseek,fd,0,1,0)==1);
    CHECK(call(__NR_close,fd,0,0,0)==0 && call(__NR_close,copy,0,0,0)==0 && query(0,0)==0);
    static const char pass[]="PASS: runtime FD exec/execveat chain, metadata, CLOEXEC, bind view and failed-exec cleanup\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
