/* Bounded active-call ownership. No global lock or guest TLS dependency. */
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <asm/unistd.h>
#include <linux/mman.h>
#include "reentry_guard.h"

/* Per process in the FD experiment, where a thread pool shares it. */
#ifdef FD_EXPERIMENT
#define GUARD_SLOTS 64
#else
#define GUARD_SLOTS 32
#endif
struct reentry_slot { long tid; };
struct guard_table { struct reentry_slot slots[GUARD_SLOTS]; };
static struct guard_table *g_table;
/* Private payload storage, shared only by the supported vfork pair. Unlike a
 * public pool slot, this slot cannot be reused by a fork sibling before the
 * suspended parent completes retirement. */
static struct reentry_slot vfork_slot;
static long vfork_tid;
/* Experimental initial task binds at first entry; private-fork children reset
 * only their own copied slot. Its other threads use the per-process table. */
static struct reentry_slot private_slot;
static long private_tid;
extern long raw_syscall(long, long, long, long, long, long, long);

/* Default build: shared anonymous storage prevents fork from copying owners
 * that only the parent can release. FD experiment: per-process storage, which
 * a private-fork child clears for its single thread. CLONE_VM threads share
 * it either way. Initialization is publish-once CAS, with no lock that a
 * nested signal could wait on. */
#ifdef FD_EXPERIMENT
#define GUARD_TABLE_MAP MAP_PRIVATE
#else
#define GUARD_TABLE_MAP MAP_SHARED
#endif
static struct guard_table *guard_table_get(void)
{
    struct guard_table *table = __atomic_load_n(&g_table, __ATOMIC_ACQUIRE);
    if (table) return table;
    long mem = raw_syscall(__NR_mmap, 0, sizeof(*table), PROT_READ | PROT_WRITE,
                          GUARD_TABLE_MAP | MAP_ANONYMOUS, -1, 0);
    if ((unsigned long)mem >= (unsigned long)-4095)
        return (struct guard_table *)(intptr_t)mem;
    struct guard_table *fresh = (void *)mem;
    table = NULL;
    if (__atomic_compare_exchange_n(&g_table, &table, fresh, 0,
                                    __ATOMIC_RELEASE, __ATOMIC_ACQUIRE))
        return fresh;
    raw_syscall(__NR_munmap, mem, sizeof(*fresh), 0, 0, 0, 0);
    return table;
}

struct reentry_slot *reentry_try_enter(void)
{
    long tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    if (tid <= 0)
        return (struct reentry_slot *)(intptr_t)(tid < 0 ? tid : -EAGAIN);
    if (__atomic_load_n(&vfork_tid, __ATOMIC_ACQUIRE) == tid) {
        long empty = 0;
        return __atomic_compare_exchange_n(&vfork_slot.tid, &empty, tid, 0,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
            ? &vfork_slot : NULL;
    }
#ifdef FD_EXPERIMENT
    /* Bind once at entry, before acquiring any lease. Binding later inside
     * dispatch would let a nested signal bypass the already-held old slot. */
    if (!__atomic_load_n(&private_tid, __ATOMIC_ACQUIRE)) {
        long empty_owner = 0;
        __atomic_compare_exchange_n(&private_tid, &empty_owner, tid, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
#endif
    if (__atomic_load_n(&private_tid, __ATOMIC_ACQUIRE) == tid) {
        long empty = 0;
        return __atomic_compare_exchange_n(&private_slot.tid, &empty, tid, 0,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
            ? &private_slot : NULL;
    }
    struct guard_table *table = guard_table_get();
    if ((uintptr_t)table >= (uintptr_t)-4095)
        return (struct reentry_slot *)table;
    struct reentry_slot *slots = table->slots;
    /* Check all owners before trying a free slot: a nested signal must not
     * allocate another slot merely because an earlier slot is free. */
    for (int i = 0; i < GUARD_SLOTS; i++)
        if (__atomic_load_n(&slots[i].tid, __ATOMIC_ACQUIRE) == tid)
            return NULL;
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < GUARD_SLOTS; i++) {
            long empty = 0;
            if (__atomic_compare_exchange_n(&slots[i].tid, &empty, tid, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return &slots[i];
        }
        /* Full: an owner that died (or was killed) inside a call never left.
         * The default build shares the table across fork, so such leases
         * accumulate over a process tree (dpkg spawns hundreds of children).
         * Only ESRCH proves death; a reused TID merely delays reclamation. */
        for (int i = 0; !pass && i < GUARD_SLOTS; i++) {
            long owner = __atomic_load_n(&slots[i].tid, __ATOMIC_ACQUIRE);
            if (owner > 0 && owner != tid &&
                raw_syscall(__NR_tkill, owner, 0, 0, 0, 0, 0) == -ESRCH)
                __atomic_compare_exchange_n(&slots[i].tid, &owner, 0, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
        }
    }
    /* Capacity is not recursion. Never silently bypass policy on exhaustion. */
    return (struct reentry_slot *)(intptr_t)-EAGAIN;
}

void reentry_leave(struct reentry_slot *slot)
{
    if (slot)
        __atomic_store_n(&slot->tid, 0, __ATOMIC_RELEASE);
}

void reentry_leave_owned(struct reentry_slot *slot, long owner)
{
    if (slot)
        __atomic_compare_exchange_n(&slot->tid, &owner, 0, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

struct reentry_slot *reentry_exec_release(void)
{
#ifdef FD_EXPERIMENT
    return NULL; /* Per-process table: exec discards it with the VM. */
#else
    struct guard_table *table = __atomic_load_n(&g_table, __ATOMIC_ACQUIRE);
    long tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    for (int i = 0; table && tid > 0 && i < GUARD_SLOTS; i++) {
        long owner = tid;
        if (__atomic_compare_exchange_n(&table->slots[i].tid, &owner, 0, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return &table->slots[i];
    }
    return NULL;
#endif
}

void reentry_exec_restore(struct reentry_slot *slot)
{
    /* Best effort: if another task took the slot meanwhile, the entry path's
     * owner-checked leave will not release it on this thread's behalf. */
    long empty = 0, tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    if (slot && tid > 0)
        __atomic_compare_exchange_n(&slot->tid, &empty, tid, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

void reentry_vfork_begin(long tid)
{
    __atomic_store_n(&vfork_slot.tid, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&vfork_tid, tid, __ATOMIC_RELEASE);
}

void reentry_vfork_end(void)
{
    /* Caller proves the child cannot execute in this VM again. No TID liveness
     * guess or public slot lookup: even an interrupted acquisition is covered. */
    __atomic_store_n(&vfork_tid, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&vfork_slot.tid, 0, __ATOMIC_RELEASE);
}

void reentry_private_fork(long tid)
{
    __atomic_store_n(&private_slot.tid, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&private_tid, tid, __ATOMIC_RELEASE);
#ifdef FD_EXPERIMENT
    /* The copied table names the parent's other threads, which do not exist
     * here; a later reuse of such a TID must not look like recursion. */
    struct guard_table *table = __atomic_load_n(&g_table, __ATOMIC_ACQUIRE);
    if (table)
        for (int i = 0; i < GUARD_SLOTS; i++)
            __atomic_store_n(&table->slots[i].tid, 0, __ATOMIC_RELEASE);
#endif
}
