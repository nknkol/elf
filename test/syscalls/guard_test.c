#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "reentry_guard.h"
static _Thread_local long simulated_tid;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f) {
    assert(n == SYS_gettid);
    return simulated_tid ? simulated_tid : syscall(n);
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
int main(void) {
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
    puts("PASS: guard reuse, recursion, capacity, 8 threads and asynchronous signals");
}
