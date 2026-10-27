/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "fd_experiment.h"
static long call(long n,long a,long b,long c,long d) {
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
#if FD_TRACK
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }
#define META(x) CHECK(x)
#else
#define META(x) ((void)0)
#endif
static volatile int marker;
static long fd,generation;
static int mode;
static char *executable;
static char stack[65536] __attribute__((aligned(16)));
extern long spawn(void *);
static long number(const char *p) { long n=0;while(*p)n=n*10+*p++-'0';return n; }
static char *decimal(char *buffer,long n) { char *p=buffer+31;*p=0;do { *--p='0'+n%10;n/=10; } while(n);return p; }
void child(void) {
    marker=1;
    if(mode==-1) {
        META(query(0,0)==0);
        call(__NR_exit,42,0,0,0);for(;;){}
    }
    META(query(0,0)==1 && query(1,fd)==generation);
#if FD_TRACK
    /* Nested private fork and nested vfork both remain unsupported. */
    CHECK(call(__NR_clone,17,0,0,0)==-ENOSYS);
    CHECK(call(__NR_clone,0x4111,0,0,0)==-ENOSYS);
#endif
    CHECK(call(__NR_fcntl,fd,F_SETFD,FD_CLOEXEC,0)==0);
    META(query(3,fd)==1);
    long duplicate=call(__NR_dup,fd,0,0,0);CHECK(duplicate>=0);
    META(query(2,duplicate)==generation && query(3,duplicate)==0);
    CHECK(call(__NR_close,fd,0,0,0)==0);
    META(query(0,0)==1 && query(1,fd)==-ENOENT);
    if(mode==0) {
        call(__NR_exit,42,0,0,0);for(;;){}
    }
    if(mode==1) {
        CHECK(call(__NR_kill,call(__NR_getpid,0,0,0,0),9,0,0)==0);for(;;){}
    }
    char digits[2][32];char *av[]={executable,"child",decimal(digits[0],duplicate),decimal(digits[1],generation),0};
    CHECK(call(__NR_execve,(long)"/missing-vfork-executable",(long)av,0,0)==-ENOENT);
    META(query(0,0)==1 && query(3,duplicate)==0);
    call(__NR_execve,(long)executable,(long)av,0,0);CHECK(0);
}
void run(long *sp) {
    char **av=(void *)(sp+1);
    if(sp[0]==4) {
        long inherited=number(av[2]),description=number(av[3]);
        META(query(0,0)==1 && query(2,inherited)==description && query(3,inherited)==0);
        (void)description;
        CHECK(call(__NR_fcntl,inherited,F_GETFD,0,0)==0);
        CHECK(call(__NR_close,inherited,0,0,0)==0);
        call(__NR_exit_group,42,0,0,0);for(;;){}
    }
    executable=av[0];mode=-1;
    long pid=spawn(stack+sizeof(stack));CHECK(pid>0 && marker==1);
    int status=0;CHECK(call(__NR_wait4,pid,(long)&status,0,0)==pid && status==(42<<8));
    META(query(0,0)==0);
    fd=call(__NR_memfd_create,(long)"vfork",0,0,0);CHECK(fd>=0);
#if FD_TRACK
    generation=query(1,fd);
#endif
    /* More execs than the 32 active-call slots: successful child exec must not
     * leak an old-VM slot, and parent records must survive repeated reuse. */
    for(int round=0;round<42;round++) {
        mode=round;marker=0;
        pid=spawn(stack+sizeof(stack));CHECK(pid>0 && marker==1);
        CHECK(call(__NR_fcntl,fd,F_GETFD,0,0)==0);
        META(query(0,0)==1 && query(1,fd)==generation && query(3,fd)==0);
        status=0;CHECK(call(__NR_wait4,pid,(long)&status,0,0)==pid);
        CHECK(status==(round==1?9:(42<<8)));
    }
    CHECK(call(__NR_close,fd,0,0,0)==0);
    static const char pass[]="PASS: runtime FD vfork shared memory, copied FDs, exit/kill/failed exec and repeated exec\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
/* Keep the parent's C stack intact. Kernel selects the child-only stack before
 * entering child(), and that function never returns to the suspended parent. */
__asm__(".global spawn\nspawn:\nstp x29,x30,[sp,#-16]!\nmov x1,x0\nmov x0,#0x4111\nmov x2,xzr\nmov x3,xzr\nmov x4,xzr\nmov x8,#220\nsvc #0\ncbz x0,1f\nldp x29,x30,[sp],#16\nret\n1: bl child\nbrk #0\n.global _start\n_start: mov x0,sp\nbl run\n");
