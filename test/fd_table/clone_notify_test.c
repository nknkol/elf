/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "clone_notify.h"
extern long notify_clone(unsigned long flags,void *stack);
struct stats {long before, parent, child, errors, maps, unmaps; int entered, proceed, stop; long orphan_pid;};
static struct stats *stats;
static int reject, fail_mapping, nested_init, probe_error, abort_child, pause_child, abort_parent;
static long pid, wait_for_child, unpublished_tid;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f)
{
    if(n==SYS_mmap && fail_mapping){fail_mapping=0;return -ENOMEM;}
    if(n==SYS_tgkill && probe_error)return -probe_error;
    if(n==SYS_mmap && nested_init) {
        nested_init=0;
        long t=clone_notify_prepare(11,22,SIGCHLD);assert(t>0);
        struct clone_return r=clone_notify_finish((void*)t,-EINVAL);
        assert(r.saved_x9==11 && r.continuation==22);
    }
    long r=syscall(n,a,b,c,d,e,f);
    if(r!=-1 && n==SYS_mmap)__atomic_add_fetch(&stats->maps,1,__ATOMIC_RELAXED);
    if(r!=-1 && n==SYS_munmap)__atomic_add_fetch(&stats->unmaps,1,__ATOMIC_RELAXED);
    return r==-1?-errno:r;
}
static void clobber(void)
{
    __asm__ volatile("msr fpcr, xzr\nmsr fpsr, xzr\nmovi v0.16b, #0\nmovi v31.16b, #0"
                     ::: "v0","v31","memory");
}
int clone_observer_before(struct clone_event *event)
{
    assert(event->parent_pid==pid && event->parent_tid==syscall(SYS_gettid));
    event->cookie=stats;
    __atomic_add_fetch(&stats->before,1,__ATOMIC_RELAXED);
    clobber();return reject?-EACCES:0;
}
void clone_observer_finish(const struct clone_event *event,long result)
{
    assert(event->cookie==stats && event->parent_pid==pid);
    if(result<0)__atomic_add_fetch(&stats->errors,1,__ATOMIC_RELAXED);
    else if(result) {
        if(abort_parent) {
            __atomic_store_n(&stats->orphan_pid,result,__ATOMIC_RELEASE);
            pthread_exit(NULL); /* real parent thread exits inside notification */
        }
        while(wait_for_child && __atomic_load_n(&stats->child,__ATOMIC_ACQUIRE)<wait_for_child)
            syscall(SYS_sched_yield);
        __atomic_add_fetch(&stats->parent,1,__ATOMIC_RELAXED);
    }
    else {
        if(pause_child) {
            __atomic_store_n(&stats->entered,1,__ATOMIC_RELEASE);
            while(!__atomic_load_n(&stats->proceed,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
        }
        if(abort_child)syscall(SYS_exit,42); /* die before releasing child role */
        __atomic_add_fetch(&stats->child,1,__ATOMIC_RELAXED);
    }
    clobber();
}
static void successful(unsigned long flags,void *stack)
{
    long child=notify_clone(flags,stack);assert(child>0);
    int status;assert(waitpid((pid_t)child,&status,0)==child);
    assert(WIFEXITED(status) && WEXITSTATUS(status)==42);
}
static void *worker(void *unused)
{
    (void)unused;
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    for(int i=0;i<16;i++)successful(CLONE_VM|SIGCHLD,(char*)stack+65536);
    assert(munmap(stack,65536)==0);return NULL;
}
static void *sweeper(void *unused)
{
    (void)unused;
    while(!__atomic_load_n(&stats->stop,__ATOMIC_ACQUIRE)) {
        assert(clone_notify_reap()==0); /* no live caller may be reclaimed */
        syscall(SYS_sched_yield);
    }
    return NULL;
}
static void *parent_exit_worker(void *stack)
{
    notify_clone(SIGCHLD,(char*)stack+65536);
    assert(0);return NULL;
}
static void *unpublished_child_worker(void *unused)
{
    (void)unused;
    unpublished_tid=syscall(SYS_gettid);
    long t=clone_notify_prepare(11,22,SIGCHLD);assert(t>0);
    return (void*)t; /* caller disappears without a kernel result */
}
static void capacity_check(void)
{
    long pending[CLONE_NOTIFY_CAPACITY];
    for(unsigned i=0;i<CLONE_NOTIFY_CAPACITY;i++) {
        pending[i]=clone_notify_prepare(i,100+i,CLONE_VM|SIGCHLD);
        assert(pending[i]>0);
    }
    assert(clone_notify_prepare(0,0,SIGCHLD)==-EAGAIN);
    assert(clone_notify_reap()==0);
    for(unsigned i=0;i<CLONE_NOTIFY_CAPACITY;i++) {
        struct clone_return r=clone_notify_finish((void*)pending[i],-EINVAL);
        assert(r.saved_x9==i && r.continuation==100+i);
    }
    long t=clone_notify_prepare(7,8,SIGCHLD);assert(t>0);
    clone_notify_finish((void*)t,-EINVAL);
}
int main(int argc,char **argv)
{
    stats=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(stats!=MAP_FAILED);pid=getpid();
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    if(argc>1 && !strcmp(argv[1],"--nested-init")) {
        nested_init=1;
        successful(SIGCHLD,NULL);
        assert(stats->maps==2 && stats->unmaps==1 && stats->before==2 && stats->errors==1);
        assert(stats->parent==1 && stats->child==1);
        puts("PASS: reentrant pool initialization loser cleanup");return 0;
    }
    fail_mapping=1;assert(notify_clone(SIGCHLD,(char*)stack+65536)==-ENOMEM);
    assert(stats->before==0 && stats->maps==0 && stats->unmaps==0);
    successful(SIGCHLD,NULL);
    successful(SIGCHLD,(char*)stack+65536);
    successful(CLONE_VM|SIGCHLD,(char*)stack+65536);
    successful(CLONE_VM|CLONE_VFORK|SIGCHLD,(char*)stack+65536);
    wait_for_child=stats->child+1;
    successful(CLONE_VM|SIGCHLD,(char*)stack+65536);
    wait_for_child=0;
    assert(stats->before==5 && stats->parent==5 && stats->child==5);
    assert(stats->maps==1 && stats->unmaps==0); /* one pool across the clone family */
    assert(notify_clone(CLONE_THREAD,(char*)stack+65536)==-EINVAL);
    assert(stats->errors==1 && stats->maps==1 && stats->unmaps==0);
    reject=1;assert(notify_clone(SIGCHLD,(char*)stack+65536)==-EACCES);reject=0;
    assert(stats->before==7 && stats->parent==5 && stats->child==5 && stats->errors==1);
    assert(stats->maps==1 && stats->unmaps==0);
    pthread_t threads[4], reaper;
    assert(pthread_create(&reaper,NULL,sweeper,NULL)==0);
    for(int i=0;i<4;i++)assert(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for(int i=0;i<4;i++)assert(pthread_join(threads[i],NULL)==0);
    assert(stats->before==71 && stats->parent==69 && stats->child==69 && stats->errors==1);
    __atomic_store_n(&stats->stop,1,__ATOMIC_RELEASE);
    assert(pthread_join(reaper,NULL)==0);
    assert(stats->maps==1 && stats->unmaps==0);
    pause_child=1;
    long child=notify_clone(CLONE_VM|SIGCHLD,(char*)stack+65536);assert(child>0);
    while(!__atomic_load_n(&stats->entered,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
    assert(clone_notify_reap()==0); /* live task inside observer */
    __atomic_store_n(&stats->proceed,1,__ATOMIC_RELEASE);
    int status;assert(waitpid((pid_t)child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==42);
    pause_child=0;
    assert(clone_notify_reap()==0);
    for(int i=0;i<3;i++) {
        abort_child=1;
        successful(CLONE_VM|SIGCHLD,(char*)stack+65536);
        abort_child=0;
        probe_error=i==0?EPERM:i==1?EAGAIN:EINVAL;
        assert(clone_notify_reap()==0); /* uncertainty never establishes death */
        probe_error=0;
        assert(clone_notify_reap()==1);
        assert(clone_notify_reap()==0); /* no duplicate completion */
    }
    /* Repeat beyond capacity without explicit reaping. prepare must reap at
     * exhaustion; callbacks that die must not grow memory without bound. */
    abort_child=1;
    for(unsigned i=0;i<CLONE_NOTIFY_CAPACITY+3;i++)
        successful(CLONE_VM|SIGCHLD,(char*)stack+65536);
    abort_child=0;
    assert(clone_notify_reap()==3);
    abort_parent=1;
    pthread_t dying;
    assert(pthread_create(&dying,NULL,parent_exit_worker,stack)==0);
    assert(pthread_join(dying,NULL)==0);
    abort_parent=0;
    long orphan=__atomic_load_n(&stats->orphan_pid,__ATOMIC_ACQUIRE);assert(orphan>0);
    assert(waitpid((pid_t)orphan,&status,0)==orphan && WIFEXITED(status) && WEXITSTATUS(status)==42);
    assert(clone_notify_reap()==1 && clone_notify_reap()==0);
    void *unknown;
    assert(pthread_create(&dying,NULL,unpublished_child_worker,NULL)==0);
    assert(pthread_join(dying,&unknown)==0);
    /* join may precede removal of the kernel task identity. */
    for(unsigned i=0;i<10000;i++) {
        if(syscall(SYS_tgkill,pid,unpublished_tid,0)==-1 && errno==ESRCH)break;
        usleep(100);
    }
    assert(syscall(SYS_tgkill,pid,unpublished_tid,0)==-1 && errno==ESRCH);
    assert(clone_notify_reap()==1 && clone_notify_reap()==0); /* only dead parent, child unknown */
    long another=clone_notify_prepare(0,0,SIGCHLD);assert(another>0 && (void*)another!=unknown);
    clone_notify_finish((void*)another,-EINVAL);
    /* Test knows no actual child was created; production cannot make this inference. */
    clone_notify_finish(unknown,-EINVAL);
    capacity_check();
    assert(stats->maps==1 && stats->unmaps==0);
    assert(munmap(stack,65536)==0 && munmap(stats,4096)==0);
    puts("PASS: clone notifications, SP/GPR/SIMD/FP state, fork/vfork, bounded pool, orphan reclamation and concurrent reaping");
    return 0;
}
