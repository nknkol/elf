/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <errno.h>
#include <stdint.h>
#include "clone_notify.h"
extern long raw_syscall(long, long, long, long, long, long, long);

/* A pin prevents reuse while a reaper inspects immutable fields. Completing
 * either task is lock-free; no lock may strand a live task behind a dead reaper.
 * INIT is unpublished and cannot be reclaimed without knowing its full state.
 * BEFORE publishes immutable identity but leaves the cookie observer-owned;
 * no kernel clone can run until that phase is cleared by result publication. */
#define PARENT_DONE CLONE_CLEANUP_PARENT_ABANDONED
#define CHILD_DONE CLONE_CLEANUP_CHILD_ABANDONED
#define ACTIVE 4u
#define BEFORE 8u
#define PIN 16u
#define INIT 1u
#define FINALIZING 2u
struct clone_transaction {
    uint64_t state;
    struct clone_return saved;
    struct clone_event event;
    unsigned abandoned;
    long child_tid; /* 0 unknown, -1 no child (kernel error), positive known */
};
struct clone_pool { struct clone_transaction slots[CLONE_NOTIFY_CAPACITY]; };
static struct clone_pool *pool;

__attribute__((weak)) int clone_observer_before(struct clone_event *event)
{ (void)event; return 0; }
__attribute__((weak)) void clone_observer_finish(const struct clone_event *event, long result)
{ (void)event; (void)result; }

__attribute__((weak)) void clone_observer_cleanup(const struct clone_event *event, unsigned reasons)
{ (void)event; (void)reasons; }

static struct clone_pool *get_pool(void)
{
    struct clone_pool *p = __atomic_load_n(&pool, __ATOMIC_ACQUIRE);
    if (p) return p;
    long mem = raw_syscall(__NR_mmap, 0, sizeof(*p), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if ((unsigned long)mem >= (unsigned long)-4095) return (void *)mem;
    struct clone_pool *fresh = (void *)mem;
    p = 0;
    if (__atomic_compare_exchange_n(&pool, &p, fresh, 0,
                                    __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
        return fresh;
    raw_syscall(__NR_munmap, mem, sizeof(*fresh), 0, 0, 0, 0);
    return p;
}

static struct clone_transaction *reserve(struct clone_pool *p)
{
    for (unsigned i = 0; i < CLONE_NOTIFY_CAPACITY; i++) {
        uint64_t empty = 0;
        if (__atomic_compare_exchange_n(&p->slots[i].state, &empty, INIT, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return &p->slots[i];
    }
    return 0;
}

static int pin(struct clone_transaction *t)
{
    uint64_t old = __atomic_load_n(&t->state, __ATOMIC_ACQUIRE);
    for (;;) {
        if (!(old & ACTIVE) || old > UINT64_MAX - PIN) return 0;
        if (__atomic_compare_exchange_n(&t->state, &old, old + PIN, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return 1;
    }
}

/* No transaction fields may be read after this call: the slot may be reused.
 * Returns only newly completed roles, so concurrent reapers cannot double-count. */
static unsigned release(struct clone_transaction *t, unsigned done, unsigned drop_pin)
{
    uint64_t old = __atomic_load_n(&t->state, __ATOMIC_ACQUIRE);
    for (;;) {
        uint64_t next = (old | done) - drop_pin;
        if ((next & ~BEFORE) == (ACTIVE | PARENT_DONE | CHILD_DONE)) next = FINALIZING;
        unsigned added = done & ~(unsigned)old;
        if (__atomic_compare_exchange_n(&t->state, &old, next, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            if (next == FINALIZING) {
                /* Exclusive finalizer: no task role or reaper can still use
                 * the event, and reserve cannot reuse it until cleanup returns. */
                /* BEFORE never transferred cookie ownership. Its partial
                 * resources belong to the observer, not this finalizer. */
                if (!(old & BEFORE))
                    clone_observer_cleanup(&t->event,
                        __atomic_load_n(&t->abandoned, __ATOMIC_ACQUIRE));
                __atomic_store_n(&t->state, 0, __ATOMIC_RELEASE);
            }
            return added;
        }
    }
}

static int gone(long pid, long tid)
{
    /* ESRCH only. EPERM and all other errors do not establish task death. A
     * reused TID may delay reclamation, but must never cause early reclamation. */
    return pid > 0 && tid > 0 &&
        raw_syscall(__NR_tgkill, pid, tid, 0, 0, 0, 0) == -ESRCH;
}

/* Our pin keeps the incarnation stable. Recheck BEFORE in the CAS: a stale
 * phase read plus a later ESRCH must not classify a post-clone death as pre-clone. */
static unsigned abandon_before(struct clone_transaction *t)
{
    uint64_t old=__atomic_load_n(&t->state,__ATOMIC_ACQUIRE);
    while(old & BEFORE) {
        uint64_t next=old|PARENT_DONE|CHILD_DONE;
        if(__atomic_compare_exchange_n(&t->state,&old,next,0,
                                      __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
            return !(old & PARENT_DONE);
    }
    return 0;
}
static void publish_before_result(struct clone_transaction *t,int rejected)
{
    uint64_t old=__atomic_load_n(&t->state,__ATOMIC_ACQUIRE);
    for(;;) {
        uint64_t next=(old & ~BEFORE)|(rejected?CHILD_DONE:0);
        if(__atomic_compare_exchange_n(&t->state,&old,next,0,
                                      __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    }
}

unsigned clone_notify_reap(void)
{
    struct clone_pool *p = __atomic_load_n(&pool, __ATOMIC_ACQUIRE);
    if (!p) return 0;
    unsigned reaped = 0;
    for (unsigned i = 0; i < CLONE_NOTIFY_CAPACITY; i++) {
        struct clone_transaction *t = &p->slots[i];
        if (!pin(t)) continue;
        uint64_t state = __atomic_load_n(&t->state, __ATOMIC_ACQUIRE);
        if (state & BEFORE) {
            if (gone(t->event.parent_pid,t->event.parent_tid))
                reaped += abandon_before(t);
            /* If publication raced the probe, leave the normal phase for a
             * fresh pass; never reuse a pre-clone liveness decision there. */
            release(t,0,PIN);
            continue;
        }
        unsigned done = 0;
        if (!(state & PARENT_DONE) && gone(t->event.parent_pid, t->event.parent_tid))
            done |= PARENT_DONE;
        long child = __atomic_load_n(&t->child_tid, __ATOMIC_ACQUIRE);
        if (!(state & CHILD_DONE) && child != 0) {
            long pid = (t->event.flags & CLONE_THREAD) ? t->event.parent_pid : child;
            if (child < 0 || gone(pid, child)) done |= CHILD_DONE;
        }
        /* Retain our pin while publishing reasons. Only newly completed roles
         * count as abandoned: a stale liveness check can race normal finish. */
        unsigned added = release(t, done, 0);
        /* A kernel error means no child existed; this is not abandonment. */
        __atomic_fetch_or(&t->abandoned, child < 0 ? added & ~CHILD_DONE : added,
                          __ATOMIC_RELAXED);
        release(t, 0, PIN);
        reaped += !!(added & PARENT_DONE) + !!(added & CHILD_DONE);
    }
    return reaped;
}

long clone_notify_prepare(unsigned long saved_x9, unsigned long continuation,
                          unsigned long flags)
{
    /* A task can disappear even during these raw identity queries. Resolve
     * them before allocating/reserving anything, so that interval cannot
     * strand an unpublished INIT slot (which the reaper cannot inspect). */
    long parent_pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    if (parent_pid <= 0) return parent_pid < 0 ? parent_pid : -EIO;
    long parent_tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    if (parent_tid <= 0) return parent_tid < 0 ? parent_tid : -EIO;
    struct clone_pool *p = get_pool();
    if ((uintptr_t)p >= (uintptr_t)-4095) return (long)p;
    struct clone_transaction *t = reserve(p);
    if (!t) {
        clone_notify_reap();
        t = reserve(p);
        if (!t) return -EAGAIN;
    }
    t->saved = (struct clone_return){saved_x9, continuation};
    t->event.flags = flags;
    t->event.parent_pid = parent_pid;
    t->event.parent_tid = parent_tid;
    t->event.cookie = 0;
    __atomic_store_n(&t->abandoned, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&t->child_tid, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&t->state,ACTIVE|BEFORE,__ATOMIC_RELEASE);
    int rc = clone_observer_before(&t->event);
    if (rc) {
        __atomic_store_n(&t->abandoned,CLONE_CLEANUP_REJECTED,__ATOMIC_RELAXED);
        publish_before_result(t,1);
        release(t,PARENT_DONE,0);
        return rc < 0 ? rc : -EINVAL;
    }
    publish_before_result(t,0);
    return (long)t;
}

struct clone_return clone_notify_finish(void *transaction, long result)
{
    struct clone_transaction *t = transaction;
    struct clone_return saved = t->saved;
    long child = result < 0 ? -1 : result ? result :
        raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    /* A failed identity lookup is uncertainty, not proof that no child exists. */
    if (result || child > 0) {
        long unknown = 0;
        __atomic_compare_exchange_n(&t->child_tid, &unknown, child, 0,
                                    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
    }
    clone_observer_finish(&t->event, result);
    release(t, result < 0 ? PARENT_DONE | CHILD_DONE :
               result ? PARENT_DONE : CHILD_DONE, 0);
    return saved;
}
