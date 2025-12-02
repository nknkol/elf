/* Lightweight TLS-like reentry guard (AArch64).
 *
 * Uses tpidr_el0 as per-thread key to prevent recursive hook entry when the
 * payload issues syscalls.
 */
#include <stddef.h>
#include <stdint.h>

#include "reentry_guard.h"

#define GUARD_SLOTS 32

struct reentry_slot {
    unsigned long tp;
    int depth;
};

static volatile int g_lock = 0;
static struct reentry_slot g_slots[GUARD_SLOTS];

static inline unsigned long read_tp(void)
{
    unsigned long tp;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    return tp;
}

static inline void lock_guard(void)
{
    while (__atomic_test_and_set(&g_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("yield" : : : "memory");
    }
}

static inline void unlock_guard(void)
{
    __atomic_clear(&g_lock, __ATOMIC_RELEASE);
}

struct reentry_slot *reentry_try_enter(void)
{
    unsigned long tp = read_tp();
    struct reentry_slot *slot = NULL;
    struct reentry_slot *free_slot = NULL;

    lock_guard();

    for (int i = 0; i < GUARD_SLOTS; i++) {
        if (g_slots[i].tp == tp) {
            slot = &g_slots[i];
            break;
        }
        if (!free_slot && g_slots[i].tp == 0)
            free_slot = &g_slots[i];
    }

    if (!slot)
        slot = free_slot;

    if (!slot) {
        unlock_guard();
        return NULL;
    }

    if (slot->tp == 0)
        slot->tp = tp;

    if (__atomic_load_n(&slot->depth, __ATOMIC_RELAXED) != 0) {
        unlock_guard();
        return NULL;
    }

    __atomic_store_n(&slot->depth, 1, __ATOMIC_RELEASE);
    unlock_guard();
    return slot;
}

void reentry_leave(struct reentry_slot *slot)
{
    if (!slot)
        return;
    __atomic_store_n(&slot->depth, 0, __ATOMIC_RELEASE);
}
