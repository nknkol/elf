/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Freestanding probe: ordinary SVC instructions, no direct payload entry. */
#include <asm/unistd.h>
#include <linux/fcntl.h>
#include <linux/sched.h>
#include <linux/mman.h>

__attribute__((noinline)) static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static void text(const char *s){long n=0;while(s[n])n++;sc(__NR_write,1,(long)s,n,0,0,0);}
static void number(long x){char b[32];int i=31;b[i--]='\n';unsigned long v=x<0?-x:x;do{b[i--]='0'+v%10;v/=10;}while(v);if(x<0)b[i--]='-';sc(__NR_write,1,(long)(b+i+1),31-i,0,0,0);}
static void report(const char *name,long value){text(name);number(value);}
static volatile long vm_marker;
struct shared {
    int tid, ready, proceed;
    long stage, pid, flags;
    long a,b,c;
};
extern long start_clone(long flags,void *stack,struct shared *state,int *tid);
void child_main(struct shared *s)
{
    s->stage=1;
    s->pid=sc(__NR_getpid,0,0,0,0,0,0);
    vm_marker=42;
    if(sc(__NR_close,s->a,0,0,0,0,0))goto done;
    s->stage=2;
    if(sc(__NR_fcntl,s->b,F_SETFD,FD_CLOEXEC,0,0,0))goto done;
    s->stage=3;
    if(sc(__NR_lseek,s->b,3,0,0,0,0)!=3)goto done;
    s->stage=4;
    if(sc(__NR_dup3,s->b,s->c,0,0,0,0)!=s->c)goto done;
    s->stage=5;
 done:
    __atomic_store_n(&s->ready,1,__ATOMIC_RELEASE);
    sc(__NR_futex,(long)&s->ready,1,1,0,0,0);
    struct {long sec,nsec;} timeout={2,0};
    while(!__atomic_load_n(&s->proceed,__ATOMIC_ACQUIRE)) {
        long r=sc(__NR_futex,(long)&s->proceed,0,0,(long)&timeout,0,0);
        if(r && r!=-11 && r!=-4){s->stage=-1;break;}
    }
    /* exit_group would kill the parent in the CLONE_THREAD scenario. */
    sc(__NR_exit,0,0,0,0,0,0);for(;;){}
}
void run(long *sp)
{
    long argc=sp[0];char **argv=(void*)(sp+1);
    int mode=argc>1?argv[1][0]-'0':-1;
    if(mode<0||mode>5)goto fail;
    long flags=17; /* SIGCHLD */
    if(mode&1)flags|=CLONE_FILES;
    if(mode&2)flags|=CLONE_VM;
    if(mode>=4)flags=CLONE_VM|CLONE_SIGHAND|CLONE_THREAD|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID;
    if(mode==4)flags|=CLONE_FILES;
    long mem=sc(__NR_mmap,0,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if((unsigned long)mem>=(unsigned long)-4095)goto fail;
    struct shared *s=(void*)mem;s->flags=flags;s->tid=-1;
    long stack=sc(__NR_mmap,0,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if((unsigned long)stack>=(unsigned long)-4095)goto fail;
    long fd=sc(__NR_memfd_create,(long)"clone-fds",0,0,0,0,0);
    if(fd<0)goto fail;
    s->a=sc(__NR_fcntl,fd,F_DUPFD,100,0,0,0);
    if(s->a<0)goto fail;
    s->b=sc(__NR_fcntl,fd,F_DUPFD,s->a+1,0,0,0);
    if(s->b<0)goto fail;
    s->c=s->b+1;
    if(sc(__NR_fcntl,s->c,F_GETFD,0,0,0,0)!=-9)goto fail;
    sc(__NR_close,fd,0,0,0,0,0);
    long pid=sc(__NR_getpid,0,0,0,0,0,0);
    report("FLAGS=",flags);
    long child=start_clone(flags,(void*)(stack+65536),s,&s->tid);
    if(child<0){report("CLONE_ERROR=",child);goto fail;}
    struct {long sec,nsec;} timeout={2,0};
    while(!__atomic_load_n(&s->ready,__ATOMIC_ACQUIRE)) {
        long r=sc(__NR_futex,(long)&s->ready,0,0,(long)&timeout,0,0);
        if(r && r!=-11 && r!=-4)goto fail;
    }
    report("STAGE=",s->stage);
    long closed=sc(__NR_fcntl,s->a,F_GETFD,0,0,0,0);
    long cloexec=sc(__NR_fcntl,s->b,F_GETFD,0,0,0,0);
    long created=sc(__NR_fcntl,s->c,F_GETFD,0,0,0,0);
    long offset=sc(__NR_lseek,s->b,0,1,0,0,0);
    report("CLOSED=",closed);report("CLOEXEC=",cloexec);report("CREATED=",created);
    report("OFFSET=",offset);report("VM=",vm_marker);report("SAME_PID=",s->pid==pid);
    __atomic_store_n(&s->proceed,1,__ATOMIC_RELEASE);
    sc(__NR_futex,(long)&s->proceed,1,1,0,0,0);
    if(mode>=4){
        int tid, ready, proceed;
        while((tid=__atomic_load_n(&s->tid,__ATOMIC_ACQUIRE))!=0) {
            long r=sc(__NR_futex,(long)&s->tid,0,tid,0,0,0);
            if(r && r!=-11 && r!=-4)goto fail;
        }
    }else{
        int status=-1;
        if(sc(__NR_wait4,child,(long)&status,0,0,0,0)!=child||status)goto fail;
    }
    if(s->stage!=5)goto fail;
    int requested_files=(flags&CLONE_FILES)!=0,vm=(flags&CLONE_VM)!=0;
    int files=closed==-9 && cloexec==1 && created==0;
    int copied=closed==0 && cloexec==0 && created==-9;
    if(!files && !copied)goto fail;
    /* Expose a host deviation rather than disguising it as Linux conformance. */
    if(files!=requested_files)text("FILES_DEVIATION=1\n");
    if(closed!=(files?-9:0)||cloexec!=(files?1:0)||created!=(files?0:-9))goto fail;
    if(offset!=3||vm_marker!=(vm?42:0)||(s->pid==pid)!=(mode>=4))goto fail;
    sc(__NR_close,s->a,0,0,0,0,0);sc(__NR_close,s->b,0,0,0,0,0);sc(__NR_close,s->c,0,0,0,0,0);
    sc(__NR_munmap,mem,4096,0,0,0,0);sc(__NR_munmap,stack,65536,0,0,0,0);
    text("CLONE_OBSERVED\n");sc(__NR_exit_group,0,0,0,0,0,0);for(;;){}
 fail:text("CLONE_FDS_FAIL\n");sc(__NR_exit_group,1,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
