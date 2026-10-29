#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include "reentry_guard.h"
static long tid=100;
static int maps;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f) {
    (void)a;(void)c;(void)d;(void)e;(void)f;
    if(n==SYS_gettid)return tid;
    /* Only sibling threads allocate the per-process table, exactly once. */
    assert(n==SYS_mmap && !maps++);
    return (long)calloc(1,(size_t)b);
}
int main(void) {
    struct reentry_slot *parent=reentry_try_enter();assert((intptr_t)parent>0);
    assert(reentry_try_enter()==NULL);
    assert(!maps); /* The initial task never touches the table. */
    /* A thread of the same process gets its own lease; its recursion is NULL. */
    tid=101;struct reentry_slot *sibling=reentry_try_enter();
    assert((intptr_t)sibling>0 && sibling!=parent && maps==1);
    assert(reentry_try_enter()==NULL);
    tid=102;struct reentry_slot *other=reentry_try_enter();
    assert((intptr_t)other>0 && other!=sibling);
    reentry_leave(other);
    reentry_vfork_begin(tid);
    struct reentry_slot *child=reentry_try_enter();assert((intptr_t)child>0 && child!=parent);
    assert(reentry_try_enter()==NULL);
    reentry_vfork_end(); /* Child died while holding its lease. */
    tid=100;assert(reentry_try_enter()==NULL);
    reentry_leave(parent);
    parent=reentry_try_enter();assert((intptr_t)parent>0);reentry_leave(parent);
    /* A private-fork child of thread 101 clears the copied table: the
     * still-held sibling lease must not make a reused TID look recursive. */
    reentry_private_fork(200);
    tid=101;struct reentry_slot *reused=reentry_try_enter();assert((intptr_t)reused>0);
    reentry_leave(reused);
    tid=200;child=reentry_try_enter();assert((intptr_t)child>0);reentry_leave(child);
    puts("PASS: private guard, per-process sibling leases, recursion, vfork and fork reset");
}
