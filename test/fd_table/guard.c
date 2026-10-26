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
#include "fd_guard.h"
#include "fd_registry.h"
struct shared {
    struct fd_guard guard;
    struct fd_registry registry;
    struct fd_task_slot tasks[8];
    struct fd_table_slot tables[8];
    struct fd_record records[32];
    unsigned completed;
};
static struct shared *s;
static volatile sig_atomic_t signal_result;
static long main_tid;
static void signal_handler(int sig)
{
    (void)sig;
    struct fd_guard_lease lease={0};
    signal_result=fd_guard_enter(&s->guard,main_tid,&lease);
}
static void *worker(void *unused)
{
    (void)unused;long tid=syscall(SYS_gettid);
    for(unsigned i=0;i<2000;i++) {
        struct fd_guard_lease lease;
        int rc;
        /* Harness retry only; production enter never waits or retries. */
        while((rc=fd_guard_enter(&s->guard,tid,&lease))==-EAGAIN)sched_yield();
        assert(rc==0);
        struct fd_task_handle h;
        assert(fd_registry_create(&s->registry,&h)==0);
        assert(fd_registry_publish(&s->registry,h,tid)==0);
        struct fd_table *t=fd_registry_table(&s->registry,h);
        assert(t && t->serial==0);
        assert(fd_table_open(t,3,(struct fd_origin){i+1,FD_ACCESS_RO},0)==0);
        assert(fd_table_dup(t,3,4,1)==0);
        assert(fd_table_get(t,4)->origin.mount_id==i+1);
        assert(fd_registry_retire(&s->registry,h)==0);
        s->completed++;
        assert(fd_guard_leave(&s->guard,lease)==0);
    }
    return NULL;
}
int main(void)
{
    s=mmap(NULL,sizeof(*s),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(s!=MAP_FAILED);
    main_tid=syscall(SYS_gettid);
    assert(fd_registry_init(&s->registry,s->tasks,8,s->tables,8,s->records,4)==0);
    struct fd_guard_lease a,b,untouched={123};
    assert(fd_guard_enter(&s->guard,main_tid,&a)==0);
    assert(fd_guard_enter(&s->guard,main_tid,&untouched)==-EDEADLK && untouched.token==123);
    struct sigaction sa={.sa_handler=signal_handler};sigemptyset(&sa.sa_mask);
    assert(sigaction(SIGUSR1,&sa,NULL)==0);
    assert(raise(SIGUSR1)==0 && signal_result==-EDEADLK);
    assert(fd_guard_leave(&s->guard,a)==0);
    assert(fd_guard_enter(&s->guard,main_tid,&b)==0);
    assert(fd_guard_leave(&s->guard,a)==-ESTALE);
    assert(fd_guard_enter(&s->guard,main_tid,&untouched)==-EDEADLK);
    assert(fd_guard_leave(&s->guard,b)==0);
    pthread_t threads[4];
    for(unsigned i=0;i<4;i++)assert(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for(unsigned i=0;i<4;i++)assert(pthread_join(threads[i],NULL)==0);
    assert(s->completed==8000);
    /* Deliberate fault injection: violating the no-syscall rule to demonstrate
     * that a fork inheritor cannot clear another task's held lease. */
    assert(fd_guard_enter(&s->guard,main_tid,&a)==0);
    int pipefd[2];assert(pipe(pipefd)==0);
    pid_t child=fork();assert(child>=0);
    if(!child) {
        long tid=syscall(SYS_gettid);
        assert(fd_guard_enter(&s->guard,tid,&b)==-EAGAIN);
        char c='x';assert(write(pipefd[1],&c,1)==1);
        while(fd_guard_enter(&s->guard,tid,&b)==-EAGAIN)sched_yield();
        s->completed++;
        assert(fd_guard_leave(&s->guard,b)==0);_exit(0);
    }
    char c;assert(read(pipefd[0],&c,1)==1);
    assert(fd_guard_leave(&s->guard,a)==0);
    int status;assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    assert(s->completed==8001);
    close(pipefd[0]);close(pipefd[1]);
    child=fork();assert(child>=0);
    if(!child) { assert(fd_guard_enter(&s->guard,syscall(SYS_gettid),&b)==0);_exit(0); }
    assert(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
    assert(fd_guard_enter(&s->guard,main_tid,&b)==-EAGAIN); /* dead owner retained */
    struct fd_guard exhausted={UINT64_C(0xffffffff00000000)};
    assert(fd_guard_enter(&exhausted,main_tid,&b)==-EOVERFLOW);
    assert(fd_guard_enter(&exhausted,0,&b)==-EINVAL);
    puts("PASS: FD metadata exclusion, 8000 concurrent registry updates, signal reentry, stale leases, fork visibility and dead-owner retention");
    return 0;
}
