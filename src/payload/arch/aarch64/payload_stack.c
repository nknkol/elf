/* SPDX-License-Identifier: GPL-2.0-or-later */
/* The stacks the intercepted calls run on (entry.S). Built with
 * -mgeneral-regs-only: entry.S calls in here before it has saved the guest's
 * SIMD registers, which it then saves on the stack claimed here.
 *
 * A guest stack can be small and its program can count on what lies just
 * below its SP being its own: a Go goroutine has a few hundred bytes there
 * at a system call (the next goroutine's stack follows), musl's posix_spawn
 * gives a vfork child about 5 KiB right above the suspended parent's frame.
 * So the guest stack holds only the stub's frame and the saved general
 * registers; everything else runs here. A stack is claimed by thread id and
 * given back on return; the parent of a vfork child that exec'd gives back
 * what the child held when vfork returns (the memory is shared), and a
 * forked child starts with none claimed. None free (or already on one, a
 * nested call): the current stack. */
#include <asm/unistd.h>
#include <errno.h>
#include "payload_stack.h"

extern long raw_syscall(long, long, long, long, long, long, long);

static struct payload_stack { long owner; void *base; } payload_stacks[PAYLOAD_STACKS];
/* Slots ever claimed: scans stop there (most processes use a few). */
static int payload_stacks_used;

void *payload_stack_claim(void)
{
    long tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    if (tid <= 0)
        return 0;
    int used = __atomic_load_n(&payload_stacks_used, __ATOMIC_ACQUIRE);
    for (int i = 0; i < used; i++)
        if (__atomic_load_n(&payload_stacks[i].owner, __ATOMIC_RELAXED) == tid)
            return 0; /* Already on it (a nested call). */
    for (int pass = 0; pass < 2; pass++)
    for (int i = 0; i < PAYLOAD_STACKS; i++) {
        /* Second pass: stacks of threads that exited holding them (a thread
         * that unmapped its own stack exits from the payload). */
        if (pass) {
            long owner = __atomic_load_n(&payload_stacks[i].owner, __ATOMIC_RELAXED);
            if (owner > 0 && raw_syscall(__NR_tgkill, raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0),
                                         owner, 0, 0, 0, 0) == -ESRCH)
                __atomic_compare_exchange_n(&payload_stacks[i].owner, &owner, 0, 0,
                                            __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        }
        struct payload_stack *s = &payload_stacks[i];
        long free_owner = 0;
        if (!__atomic_compare_exchange_n(&s->owner, &free_owner, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            continue;
        int seen = __atomic_load_n(&payload_stacks_used, __ATOMIC_RELAXED);
        while (seen <= i && !__atomic_compare_exchange_n(&payload_stacks_used, &seen, i + 1, 0,
                                                         __ATOMIC_RELEASE, __ATOMIC_RELAXED))
            ;
        void *base = __atomic_load_n(&s->base, __ATOMIC_ACQUIRE);
        if (!base) {
            long mem = raw_syscall(__NR_mmap, 0, PAYLOAD_STACK_SIZE, 3, 0x22, -1, 0);
            if ((unsigned long)mem >= (unsigned long)-4095) {
                __atomic_store_n(&s->owner, 0, __ATOMIC_RELEASE);
                return 0;
            }
            base = (void *)mem;
            __atomic_store_n(&s->base, base, __ATOMIC_RELEASE);
        }
        return (char *)base + PAYLOAD_STACK_SIZE;
    }
    return 0;
}

void payload_stack_release(void *top)
{
    if (!top)
        return;
    int used = __atomic_load_n(&payload_stacks_used, __ATOMIC_ACQUIRE);
    for (int i = 0; i < used; i++)
        if ((char *)__atomic_load_n(&payload_stacks[i].base, __ATOMIC_RELAXED) + PAYLOAD_STACK_SIZE == top) {
            __atomic_store_n(&payload_stacks[i].owner, 0, __ATOMIC_RELEASE);
            return;
        }
}

void payload_stack_clone_finish(unsigned long flags, long result)
{
    if (result < 0)
        return;
    int used = __atomic_load_n(&payload_stacks_used, __ATOMIC_ACQUIRE);
    for (int i = 0; i < used; i++) {
        if (!result && !(flags & 0x100 /* CLONE_VM */)) {
            /* A private copy: the claims are other threads' of the parent. */
            payload_stacks[i].owner = 0;
        } else if (result && (flags & 0x4000 /* CLONE_VFORK */)) {
            long child = result;
            __atomic_compare_exchange_n(&payload_stacks[i].owner, &child, 0, 0,
                                        __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        }
    }
}
