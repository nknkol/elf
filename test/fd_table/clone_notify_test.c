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
struct resource { int live; };
struct stats {long cleaned, rejected, abandoned_parent, abandoned_child; struct resource resources[128]; long before, parent, child, errors, maps, unmaps; int entered, proceed, stop; long orphan_pid;};
static struct stats *stats;
static int reject, fail_mapping, nested_init, probe_error, abort_child, pause_child, abort_parent;
static long pid, wait_for_child, unpublished_tid;
static long identity_exit, identity_fail, identity_result;
static int before_exit;
static long before_tid;
static int before_pause, before_ready, before_release, probe_advance;
static pthread_t phase_thread;
static void *phase_transaction;
static int cleanup_pause, cleanup_entered, cleanup_proceed, cleanup_exit, cleanup_nested;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f)
{
    if(n==SYS_tgkill && probe_advance) {
        probe_advance=0;
        __atomic_store_n(&before_release,1,__ATOMIC_RELEASE);
        assert(pthread_join(phase_thread,&phase_transaction)==0);
        for(unsigned i=0;i<10000;i++) {
            if(syscall(SYS_tgkill,a,b,0)==-1 && errno==ESRCH)return -ESRCH;
            usleep(100);
        }
        assert(0);
    }
    if(n==identity_exit)pthread_exit((void *)1);
    if(n==identity_fail)return identity_result;
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
    event->cookie=NULL;
    if(before_exit==1)pthread_exit(NULL);
    for(unsigned i=0;i<128;i++) {
        int empty=0;
        if(__atomic_compare_exchange_n(&stats->resources[i].live,&empty,1,0,
                                      __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
            event->cookie=&stats->resources[i];break;
        }
    }
    assert(event->cookie);
    __atomic_add_fetch(&stats->before,1,__ATOMIC_RELAXED);
    if(before_exit==2)pthread_exit(NULL);
    if(before_pause) {
        __atomic_store_n(&before_ready,1,__ATOMIC_RELEASE);
        while(!__atomic_load_n(&before_release,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
    }
    clobber();return reject?-EACCES:0;
}
void clone_observer_finish(const struct clone_event *event,long result)
{
    assert(event->cookie && event->parent_pid==pid);
    assert(__atomic_load_n(&((struct resource*)event->cookie)->live,__ATOMIC_ACQUIRE)==1);
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
void clone_observer_cleanup(const struct clone_event *event,unsigned reasons)
{
    assert(event->cookie && event->parent_pid==pid);
    if(__atomic_exchange_n(&cleanup_pause,0,__ATOMIC_ACQ_REL)) {
        __atomic_store_n(&cleanup_entered,1,__ATOMIC_RELEASE);
        while(!__atomic_load_n(&cleanup_proceed,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
    }
    if(cleanup_exit)pthread_exit(NULL);
    if(cleanup_nested) {
        cleanup_nested=0;
        long nested=clone_notify_prepare(3,4,SIGCHLD);assert(nested>0);
        clone_notify_finish((void*)nested,-EINVAL);
    }
    assert(!(reasons & ~(CLONE_CLEANUP_PARENT_ABANDONED |
                        CLONE_CLEANUP_CHILD_ABANDONED | CLONE_CLEANUP_REJECTED)));
    assert(__atomic_exchange_n(&((struct resource*)event->cookie)->live,0,__ATOMIC_ACQ_REL)==1);
    __atomic_add_fetch(&stats->cleaned,1,__ATOMIC_RELAXED);
    if(reasons & CLONE_CLEANUP_REJECTED)__atomic_add_fetch(&stats->rejected,1,__ATOMIC_RELAXED);
    if(reasons & CLONE_CLEANUP_PARENT_ABANDONED)__atomic_add_fetch(&stats->abandoned_parent,1,__ATOMIC_RELAXED);
    if(reasons & CLONE_CLEANUP_CHILD_ABANDONED)__atomic_add_fetch(&stats->abandoned_child,1,__ATOMIC_RELAXED);
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
static void *cleanup_worker(void *unused)
{
    (void)unused;
    long t=clone_notify_prepare(1,2,SIGCHLD);assert(t>0);
    clone_notify_finish((void*)t,-EINVAL);
    return NULL;
}
static void cleanup_checks(int die)
{
    pthread_t worker;
    cleanup_exit=die;cleanup_pause=!die;
    assert(pthread_create(&worker,NULL,cleanup_worker,NULL)==0);
    if(die)assert(pthread_join(worker,NULL)==0);
    else while(!__atomic_load_n(&cleanup_entered,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
    assert(stats->cleaned==0);
    assert(clone_notify_reap()==0);
    long pending[CLONE_NOTIFY_CAPACITY-1];
    for(unsigned i=0;i<CLONE_NOTIFY_CAPACITY-1;i++) {
        pending[i]=clone_notify_prepare(i,0,SIGCHLD);assert(pending[i]>0);
    }
    assert(clone_notify_prepare(0,0,SIGCHLD)==-EAGAIN); /* finalizer still owns one */
    if(!die) {
        __atomic_store_n(&cleanup_proceed,1,__ATOMIC_RELEASE);
        assert(pthread_join(worker,NULL)==0);
    }
    cleanup_exit=0;
    for(unsigned i=0;i<CLONE_NOTIFY_CAPACITY-1;i++)clone_notify_finish((void*)pending[i],-EINVAL);
    cleanup_nested=1;
    cleanup_worker(NULL); /* cleanup can reenter without reusing its own slot */
    assert(stats->before==stats->cleaned+die);
    assert(clone_notify_reap()==0); /* abandoned cleanup is not retried */
    puts(die?"PASS: abandoned finalizer retained without duplicate cleanup":
             "PASS: exclusive finalizer, deferred slot reuse and reentrant cleanup");
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
static void *identity_worker(void *unused)
{
    (void)unused;
    clone_notify_prepare(0,0,SIGCHLD);
    assert(0);return NULL; /* Must exit inside the identity query, not exhaust. */
}
static void identity_checks(void)
{
    const long calls[]={SYS_getpid,SYS_gettid};
    for(unsigned n=0;n<2;n++) {
        identity_exit=calls[n];
        for(unsigned i=0;i<CLONE_NOTIFY_CAPACITY+3;i++) {
            pthread_t worker;void *result=NULL;
            assert(pthread_create(&worker,NULL,identity_worker,NULL)==0);
            assert(pthread_join(worker,&result)==0 && result==(void *)1);
        }
        identity_exit=0;
        assert(stats->before==0 && stats->maps==0 && clone_notify_reap()==0);
        identity_fail=calls[n];
        identity_result=-EINTR;assert(clone_notify_prepare(0,0,SIGCHLD)==-EINTR);
        identity_result=0;assert(clone_notify_prepare(0,0,SIGCHLD)==-EIO);
        identity_fail=0;
    }
    capacity_check();
    assert(stats->before==stats->cleaned && stats->maps==1);
    puts("PASS: identity-query death/errors reserve no clone slots; full capacity remains");
}
static void *before_worker(void *unused)
{
    (void)unused;before_tid=syscall(SYS_gettid);
    clone_notify_prepare(0,0,SIGCHLD);assert(0);return NULL;
}
static void *phase_worker(void *unused)
{
    (void)unused;
    long t=clone_notify_prepare(7,8,SIGCHLD);assert(t>0);
    return (void *)t; /* Prepare returned, kernel outcome remains unknown. */
}
static void phase_race_checks(void)
{
    before_pause=1;
    assert(pthread_create(&phase_thread,NULL,phase_worker,NULL)==0);
    while(!__atomic_load_n(&before_ready,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
    assert(clone_notify_reap()==0); /* A live before callback keeps its slot. */
    probe_advance=1;
    assert(clone_notify_reap()==0); /* Stale BEFORE read must not prove no child. */
    before_pause=0;
    assert(stats->cleaned==0 && phase_transaction);
    assert(clone_notify_reap()==1 && clone_notify_reap()==0);
    assert(stats->cleaned==0); /* Unknown child still prevents reclamation. */
    clone_notify_finish(phase_transaction,-EINVAL); /* Test knows no clone ran. */
    assert(stats->cleaned==1);
    capacity_check();
    puts("PASS: live before callback and phase-publication race retain unknown child");
}
static void await_before_death(void)
{
    for(unsigned retry=0;retry<10000;retry++) {
        if(syscall(SYS_tgkill,pid,before_tid,0)==-1 && errno==ESRCH)break;
        usleep(100);
    }
    assert(syscall(SYS_tgkill,pid,before_tid,0)==-1 && errno==ESRCH);
}
static void before_checks(void)
{
    for(int stage=1;stage<=2;stage++) {
        before_exit=stage;
        for(unsigned i=0;i<CLONE_NOTIFY_CAPACITY+3;i++) {
            pthread_t worker;
            assert(pthread_create(&worker,NULL,before_worker,NULL)==0);
            assert(pthread_join(worker,NULL)==0);
            await_before_death();
            probe_error=EPERM;assert(clone_notify_reap()==0);probe_error=0;
            assert(clone_notify_reap()==1 && clone_notify_reap()==0);
            assert(stats->cleaned==0); /* Partial cookies never enter cleanup. */
            unsigned partial=0;
            for(unsigned j=0;j<128;j++)
                partial+=__atomic_exchange_n(&stats->resources[j].live,0,__ATOMIC_ACQ_REL);
            assert(partial==(unsigned)(stage==2)); /* Observer-owned repair. */
        }
    }
    /* No explicit reaping until capacity pressure triggers prepare's sweep. */
    before_exit=1;
    for(unsigned i=0;i<CLONE_NOTIFY_CAPACITY+3;i++) {
        pthread_t worker;
        assert(pthread_create(&worker,NULL,before_worker,NULL)==0);
        assert(pthread_join(worker,NULL)==0);await_before_death();
    }
    before_exit=0;
    assert(clone_notify_reap()==3 && clone_notify_reap()==0 && stats->cleaned==0);
    long abandoned=stats->before;
    capacity_check();
    assert(stats->before==stats->cleaned+abandoned && stats->maps==1);
    puts("PASS: before-callback death reclaims slots without claiming partial cookies");
}
int main(int argc,char **argv)
{
    stats=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(stats!=MAP_FAILED);pid=getpid();
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    if(argc>1 && !strcmp(argv[1],"--phase-race")) { phase_race_checks();return 0; }
    if(argc>1 && !strcmp(argv[1],"--before-exit")) { before_checks();return 0; }
    if(argc>1 && !strcmp(argv[1],"--identity-exit")) { identity_checks();return 0; }
    if(argc>1 && (!strcmp(argv[1],"--cleanup-exit") || !strcmp(argv[1],"--cleanup-pause"))) {
        cleanup_checks(!strcmp(argv[1],"--cleanup-exit"));return 0;
    }
    if(argc>1 && !strcmp(argv[1],"--nested-init")) {
        nested_init=1;
        successful(SIGCHLD,NULL);
        assert(stats->maps==2 && stats->unmaps==1 && stats->before==2 && stats->errors==1);
        assert(stats->parent==1 && stats->child==1);
        assert(stats->cleaned==2);
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
    assert(stats->cleaned==7 && stats->rejected==1);
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
    assert(stats->cleaned==stats->before);
    pause_child=1;
    long child=notify_clone(CLONE_VM|SIGCHLD,(char*)stack+65536);assert(child>0);
    while(!__atomic_load_n(&stats->entered,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
    assert(clone_notify_reap()==0); /* live task inside observer */
    assert(stats->cleaned==stats->before-1);
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
    assert(stats->cleaned==stats->before-1); /* unknown child keeps cookie alive */
    long another=clone_notify_prepare(0,0,SIGCHLD);assert(another>0 && (void*)another!=unknown);
    clone_notify_finish((void*)another,-EINVAL);
    /* Test knows no actual child was created; production cannot make this inference. */
    clone_notify_finish(unknown,-EINVAL);
    capacity_check();
    assert(stats->cleaned==stats->before && stats->rejected==1);
    assert(stats->abandoned_parent==2 && stats->abandoned_child==CLONE_NOTIFY_CAPACITY+6);
    for(unsigned i=0;i<128;i++)assert(stats->resources[i].live==0);
    assert(stats->maps==1 && stats->unmaps==0);
    assert(munmap(stack,65536)==0 && munmap(stats,4096)==0);
    puts("PASS: clone notifications, SP/GPR/SIMD/FP state, fork/vfork, bounded pool, orphan reclamation and concurrent reaping");
    return 0;
}
