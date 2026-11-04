/* Bounded active-call ownership. No global lock or guest TLS dependency. */
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <asm/unistd.h>
#include <linux/mman.h>
#include "reentry_guard.h"

/* One slot per thread inside a call. Threads can be many at once, each
 * blocked in a call (a Go program: one thread per blocked goroutine); a
 * full table refused the next call with EAGAIN. Scans stop at `used`, the
 * most slots ever held at once, so a few threads cost what they did. */
#define GUARD_SLOTS 1024
struct reentry_slot { long tid; };
struct guard_table { int used; struct reentry_slot slots[GUARD_SLOTS]; };
static struct guard_table *g_table;
/* Private payload storage, shared only by the supported vfork pair. Unlike a
 * public pool slot, this slot cannot be reused by a fork sibling before the
 * suspended parent completes retirement. */
static struct vfork_lease { long tid; struct reentry_slot slot; } vfork_leases[REENTRY_VFORKS];
static int vfork_count; /* leases held: no scan while none */
/* Experimental initial task binds at first entry; private-fork children reset
 * only their own copied slot. Its other threads use the per-process table. */
static struct reentry_slot private_slot;
static long private_tid;
extern long raw_syscall(long, long, long, long, long, long, long);

/* Per-process storage in both builds; CLONE_VM threads share it. A shared
 * table spanned the whole process tree, so 32 processes blocked in pipe reads
 * exhausted it for everyone. A fork child's copy may still name its parent's
 * other threads: a full table reclaims owners that are not live threads of
 * this process. The FD experiment's private-fork child also clears its copy.
 * Initialization is publish-once CAS, with no lock that a nested signal
 * could wait on. */
#define GUARD_TABLE_MAP MAP_PRIVATE
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
    for (int i = 0; __atomic_load_n(&vfork_count, __ATOMIC_ACQUIRE) && i < REENTRY_VFORKS; i++) {
        if (__atomic_load_n(&vfork_leases[i].tid, __ATOMIC_ACQUIRE) != tid)
            continue;
        long empty = 0;
        return __atomic_compare_exchange_n(&vfork_leases[i].slot.tid, &empty, tid, 0,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)
            ? &vfork_leases[i].slot : NULL;
    }
#ifdef GUARDED
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
     * allocate another slot merely because an earlier slot is free. A slot
     * is held only after `used` covers it (set before the claim below). */
    int used = __atomic_load_n(&table->used, __ATOMIC_ACQUIRE);
    for (int i = 0; i < used; i++)
        if (__atomic_load_n(&slots[i].tid, __ATOMIC_ACQUIRE) == tid)
            return NULL;
    for (int pass = 0; pass < 2; pass++) {
        for (int i = 0; i < GUARD_SLOTS; i++) {
            if (__atomic_load_n(&slots[i].tid, __ATOMIC_RELAXED))
                continue;
            int seen = __atomic_load_n(&table->used, __ATOMIC_RELAXED);
            while (seen <= i && !__atomic_compare_exchange_n(&table->used, &seen, i + 1, 0,
                                                             __ATOMIC_RELEASE, __ATOMIC_RELAXED))
                ;
            long empty = 0;
            if (__atomic_compare_exchange_n(&slots[i].tid, &empty, tid, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return &slots[i];
        }
        /* Full: an owner that died inside a call never left, and a fork
         * child's copy names its parent's threads. Only ESRCH from this
         * thread group proves either; a reused TID merely delays it. */
        long pid = pass ? 0 : raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        for (int i = 0; !pass && pid > 0 && i < GUARD_SLOTS; i++) {
            long owner = __atomic_load_n(&slots[i].tid, __ATOMIC_ACQUIRE);
            if (owner > 0 && owner != tid &&
                raw_syscall(__NR_tgkill, pid, owner, 0, 0, 0, 0) == -ESRCH)
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
#ifdef GUARDED
    return NULL; /* The FD experiment's exec path manages its own leases. */
#else
    /* A vfork child shares this VM: its lease must not outlive its exec. */
    struct guard_table *table = __atomic_load_n(&g_table, __ATOMIC_ACQUIRE);
    long tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    int used = table ? __atomic_load_n(&table->used, __ATOMIC_ACQUIRE) : 0;
    for (int i = 0; tid > 0 && i < used; i++) {
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
    for (int i = 0; i < REENTRY_VFORKS; i++) {
        long free_owner = 0;
        if (!__atomic_compare_exchange_n(&vfork_leases[i].tid, &free_owner, tid, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        __atomic_store_n(&vfork_leases[i].slot.tid, 0, __ATOMIC_RELEASE);
        __atomic_add_fetch(&vfork_count, 1, __ATOMIC_ACQ_REL);
        return;
    }
}

void reentry_vfork_end(long tid)
{
    /* Caller proves the child cannot execute in this VM again. No TID liveness
     * guess or public slot lookup: even an interrupted acquisition is covered. */
    for (int i = 0; tid > 0 && i < REENTRY_VFORKS; i++) {
        if (__atomic_load_n(&vfork_leases[i].tid, __ATOMIC_ACQUIRE) != tid)
            continue;
        __atomic_store_n(&vfork_leases[i].slot.tid, 0, __ATOMIC_RELEASE);
        __atomic_store_n(&vfork_leases[i].tid, 0, __ATOMIC_RELEASE);
        __atomic_sub_fetch(&vfork_count, 1, __ATOMIC_ACQ_REL);
        return;
    }
}

void reentry_private_fork(long tid)
{
    __atomic_store_n(&private_slot.tid, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&private_tid, tid, __ATOMIC_RELEASE);
#ifdef GUARDED
    /* The copied table names the parent's other threads, which do not exist
     * here; a later reuse of such a TID must not look like recursion. */
    struct guard_table *table = __atomic_load_n(&g_table, __ATOMIC_ACQUIRE);
    if (table)
        for (int i = 0; i < __atomic_load_n(&table->used, __ATOMIC_ACQUIRE); i++)
            __atomic_store_n(&table->slots[i].tid, 0, __ATOMIC_RELEASE);
#endif
}
