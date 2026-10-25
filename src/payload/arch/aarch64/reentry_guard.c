/* Bounded active-call ownership. No global lock or guest TLS dependency. */
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <asm/unistd.h>
#include "reentry_guard.h"

#define GUARD_SLOTS 32
struct reentry_slot { long tid; };
static struct reentry_slot g_slots[GUARD_SLOTS];
extern long raw_syscall(long, long, long, long, long, long, long);

struct reentry_slot *reentry_try_enter(void)
{
    long tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    if (tid <= 0)
        return (struct reentry_slot *)(intptr_t)(tid < 0 ? tid : -EAGAIN);
    /* Check all owners before trying a free slot: a nested signal must not
     * allocate another slot merely because an earlier slot is free. */
    for (int i = 0; i < GUARD_SLOTS; i++)
        if (__atomic_load_n(&g_slots[i].tid, __ATOMIC_ACQUIRE) == tid)
            return NULL;
    for (int i = 0; i < GUARD_SLOTS; i++) {
        long empty = 0;
        if (__atomic_compare_exchange_n(&g_slots[i].tid, &empty, tid, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return &g_slots[i];
    }
    /* Capacity is not recursion. Never silently bypass policy on exhaustion. */
    return (struct reentry_slot *)(intptr_t)-EAGAIN;
}

void reentry_leave(struct reentry_slot *slot)
{
    if (slot)
        __atomic_store_n(&slot->tid, 0, __ATOMIC_RELEASE);
}
