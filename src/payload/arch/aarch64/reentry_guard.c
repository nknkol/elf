/* Bounded active-call ownership. No global lock or guest TLS dependency. */
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <asm/unistd.h>
#include <linux/mman.h>
#include "reentry_guard.h"

#define GUARD_SLOTS 32
struct reentry_slot { long tid; };
struct guard_table { struct reentry_slot slots[GUARD_SLOTS]; };
static struct guard_table *g_table;
/* Private payload storage, shared only by the supported vfork pair. Unlike a
 * public pool slot, this slot cannot be reused by a fork sibling before the
 * suspended parent completes retirement. */
static struct reentry_slot vfork_slot;
static long vfork_tid;
/* Enabled only by the private-fork child callback, never for general threads.
 * A nested fork copies this slot; its child resets only its private copy. */
static struct reentry_slot private_slot;
static long private_tid;
extern long raw_syscall(long, long, long, long, long, long, long);

/* Shared anonymous storage prevents fork from copying owners that only the
 * parent can release. CLONE_VM users naturally share it too. Initialization
 * is publish-once CAS, with no lock that a nested signal could wait on. */
static struct guard_table *guard_table_get(void)
{
    struct guard_table *table = __atomic_load_n(&g_table, __ATOMIC_ACQUIRE);
    if (table) return table;
    long mem = raw_syscall(__NR_mmap, 0, sizeof(*table), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
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
    for (int i = 0; i < GUARD_SLOTS; i++) {
        long empty = 0;
        if (__atomic_compare_exchange_n(&slots[i].tid, &empty, tid, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return &slots[i];
    }
    /* Capacity is not recursion. Never silently bypass policy on exhaustion. */
    return (struct reentry_slot *)(intptr_t)-EAGAIN;
}

void reentry_leave(struct reentry_slot *slot)
{
    if (slot)
        __atomic_store_n(&slot->tid, 0, __ATOMIC_RELEASE);
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
}
