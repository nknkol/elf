#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include "reentry_guard.h"
static long tid=100;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    /* Experimental entry must not allocate or use the shared guard table. */
    assert(n==SYS_gettid);return tid;
}
int main(void) {
    struct reentry_slot *parent=reentry_try_enter();assert((intptr_t)parent>0);
    assert(reentry_try_enter()==NULL);
    tid=101;assert((intptr_t)reentry_try_enter()==-EOPNOTSUPP);
    reentry_vfork_begin(tid);
    struct reentry_slot *child=reentry_try_enter();assert((intptr_t)child>0 && child!=parent);
    assert(reentry_try_enter()==NULL);
    reentry_vfork_end(); /* Child died while holding its lease. */
    tid=100;assert(reentry_try_enter()==NULL);
    reentry_leave(parent);
    parent=reentry_try_enter();assert((intptr_t)parent>0);reentry_leave(parent);
    puts("PASS: initial private guard, recursion, unsupported sibling and vfork retirement");
}
