#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "reentry_guard.h"
static _Thread_local long simulated_tid;
static int fail_mapping, nested_init;
static int live_mappings;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f) {
    if(n == SYS_gettid)return simulated_tid ? simulated_tid : syscall(n);
    assert(n == SYS_mmap || n == SYS_munmap);
    if(n==SYS_mmap && fail_mapping){fail_mapping=0;return -ENOMEM;}
    if(n==SYS_mmap && nested_init) {
        nested_init=0;
        struct reentry_slot *s=reentry_try_enter();
        assert((intptr_t)s>0);reentry_leave(s);
    }
    long result=syscall(n,a,b,c,d,e,f);
    if(result!=-1)__atomic_add_fetch(&live_mappings,n==SYS_mmap?1:-1,__ATOMIC_RELAXED);
    return result==-1 ? -errno : result;
}
static volatile sig_atomic_t signals_seen;
static void handler(int sig) {
    (void)sig;
    struct reentry_slot *slot = reentry_try_enter();
    assert((intptr_t)slot >= 0);
    if (slot) reentry_leave(slot);
    signals_seen++;
}
static void *worker(void *arg) {
    (void)arg;
    for (int i=0;i<10000;i++) {
        struct reentry_slot *s=reentry_try_enter();
        assert((intptr_t)s>0);
        assert(reentry_try_enter()==NULL);
        reentry_leave(s);
    }
    return NULL;
}
static void *sender(void *arg) {
    pthread_t target=*(pthread_t*)arg;
    for(int i=0;i<20000;i++) assert(pthread_kill(target,SIGUSR1)==0);
    return NULL;
}
static int fork_ownership(void) {
    struct reentry_slot *held[32];
    for(int i=0;i<32;i++) {
        simulated_tid=2000+i;
        held[i]=reentry_try_enter();assert((intptr_t)held[i]>0);
    }
    simulated_tid=0;
    int ready[2], proceed[2];assert(!pipe(ready));assert(!pipe(proceed));
    pid_t pid=fork();assert(pid>=0);
    if(!pid) {
        close(ready[0]);close(proceed[1]);
        /* Parent owners must not be mistaken for recursion or erased. */
        if((intptr_t)reentry_try_enter()!=-EAGAIN)_exit(10);
        char byte='x';if(write(ready[1],&byte,1)!=1)_exit(11);
        if(read(proceed[0],&byte,1)!=1)_exit(12);
        /* After parent releases, a copied private table incorrectly stays full. */
        struct reentry_slot *s=reentry_try_enter();
        if((intptr_t)s<=0)_exit(13);
        if(reentry_try_enter()!=NULL)_exit(14);
        reentry_leave(s);_exit(0);
    }
    close(ready[1]);close(proceed[0]);char byte;
    assert(read(ready[0],&byte,1)==1);
    for(int i=0;i<32;i++)reentry_leave(held[i]);
    assert(write(proceed[1],"x",1)==1);
    int status;assert(waitpid(pid,&status,0)==pid);
    close(ready[0]);close(proceed[1]);
    if(!WIFEXITED(status)||WEXITSTATUS(status)) {
        fprintf(stderr,"FAIL: fork copied stale owners, child status=%d\n",status);
        return 1;
    }
    return 0;
}
int main(int argc,char **argv) {
    (void)argv;
    fail_mapping=1;
    assert((intptr_t)reentry_try_enter()==-ENOMEM);
    assert(live_mappings==0);
    if(argc>1) {
        nested_init=1;
        struct reentry_slot *s=reentry_try_enter();assert((intptr_t)s>0);
        reentry_leave(s);assert(live_mappings==1);
        puts("PASS: failed mapping retry and nested initialization loser cleanup");
        return 0;
    }
    /* Multiple threads race to initialize before any table has been published. */
    pthread_t starters[8];
    for(int i=0;i<8;i++)assert(!pthread_create(&starters[i],NULL,worker,NULL));
    for(int i=0;i<8;i++)assert(!pthread_join(starters[i],NULL));
    assert(live_mappings==1);
    struct reentry_slot *held[32];
    for(int i=0;i<1024;i++) {
        simulated_tid=1000+i;
        struct reentry_slot *s=reentry_try_enter();assert((intptr_t)s>0);
        assert(reentry_try_enter()==NULL);reentry_leave(s);
    }
    for(int i=0;i<32;i++) {simulated_tid=100+i;held[i]=reentry_try_enter();assert((intptr_t)held[i]>0);}
    simulated_tid=999;assert((intptr_t)reentry_try_enter()==-EAGAIN);
    reentry_leave(held[0]);simulated_tid=131;
    assert(reentry_try_enter()==NULL); /* Existing owner after a free hole. */
    simulated_tid=999;held[0]=reentry_try_enter();assert((intptr_t)held[0]>0);
    for(int i=0;i<32;i++)reentry_leave(held[i]);
    simulated_tid=0;
    pthread_t workers[8];
    for(int i=0;i<8;i++)assert(!pthread_create(&workers[i],NULL,worker,NULL));
    for(int i=0;i<8;i++)assert(!pthread_join(workers[i],NULL));
    struct sigaction act={0};act.sa_handler=handler;sigemptyset(&act.sa_mask);
    assert(!sigaction(SIGUSR1,&act,NULL));
    pthread_t main_thread=pthread_self(), thread;
    assert(!pthread_create(&thread,NULL,sender,&main_thread));
    worker(NULL);
    assert(!pthread_join(thread,NULL));assert(signals_seen>0);
    if(fork_ownership())return 1;
    puts("PASS: fork ownership, guard reuse, recursion, capacity, 8 threads and asynchronous signals");
}
