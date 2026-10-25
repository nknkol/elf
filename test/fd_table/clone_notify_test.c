/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "clone_notify.h"
extern long notify_clone(unsigned long flags,void *stack);
struct stats {long before, parent, child, errors, maps, unmaps;};
static struct stats *stats;
static int reject, fail_mapping;
static long pid, wait_for_child;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f)
{
    if(n==SYS_mmap && fail_mapping){fail_mapping=0;return -ENOMEM;}
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
        while(wait_for_child && __atomic_load_n(&stats->child,__ATOMIC_ACQUIRE)<wait_for_child)
            syscall(SYS_sched_yield);
        __atomic_add_fetch(&stats->parent,1,__ATOMIC_RELAXED);
    }
    else __atomic_add_fetch(&stats->child,1,__ATOMIC_RELAXED);
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
int main(void)
{
    stats=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(stats!=MAP_FAILED);pid=getpid();
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    successful(SIGCHLD,NULL);
    successful(SIGCHLD,(char*)stack+65536);
    successful(CLONE_VM|SIGCHLD,(char*)stack+65536);
    successful(CLONE_VM|CLONE_VFORK|SIGCHLD,(char*)stack+65536);
    wait_for_child=stats->child+1;
    successful(CLONE_VM|SIGCHLD,(char*)stack+65536);
    wait_for_child=0;
    assert(stats->before==5 && stats->parent==5 && stats->child==5);
    assert(stats->maps==5 && stats->unmaps==7); /* each copied VM unmaps its copy */
    assert(notify_clone(CLONE_THREAD,(char*)stack+65536)==-EINVAL);
    assert(stats->errors==1 && stats->maps==6 && stats->unmaps==8);
    reject=1;assert(notify_clone(SIGCHLD,(char*)stack+65536)==-EACCES);reject=0;
    assert(stats->before==7 && stats->parent==5 && stats->child==5 && stats->errors==1);
    assert(stats->maps==7 && stats->unmaps==9);
    fail_mapping=1;assert(notify_clone(SIGCHLD,(char*)stack+65536)==-ENOMEM);
    assert(stats->before==7 && stats->maps==7 && stats->unmaps==9);
    pthread_t threads[4];
    for(int i=0;i<4;i++)assert(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for(int i=0;i<4;i++)assert(pthread_join(threads[i],NULL)==0);
    assert(stats->before==71 && stats->parent==69 && stats->child==69 && stats->errors==1);
    assert(stats->maps==71 && stats->unmaps==73);
    assert(munmap(stack,65536)==0 && munmap(stats,4096)==0);
    puts("PASS: clone notifications, SP/GPR/SIMD/FP state, fork/vfork, failure cleanup and 4 concurrent callers");
    return 0;
}
