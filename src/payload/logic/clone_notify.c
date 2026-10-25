/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <errno.h>
#include "clone_notify.h"
extern long raw_syscall(long, long, long, long, long, long, long);
struct clone_transaction {
    struct clone_return saved;
    struct clone_event event;
    unsigned remaining;
};
#define TRANSACTION_BYTES 4096
_Static_assert(sizeof(struct clone_transaction) <= TRANSACTION_BYTES, "clone context size");

__attribute__((weak)) int clone_observer_before(struct clone_event *event)
{ (void)event; return 0; }
__attribute__((weak)) void clone_observer_finish(const struct clone_event *event, long result)
{ (void)event; (void)result; }

long clone_notify_prepare(unsigned long saved_x9, unsigned long continuation,
                          unsigned long flags)
{
    long mem = raw_syscall(__NR_mmap, 0, TRANSACTION_BYTES, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if ((unsigned long)mem >= (unsigned long)-4095) return mem;
    struct clone_transaction *t = (void *)mem;
    t->saved = (struct clone_return){saved_x9, continuation};
    t->event.flags = flags;
    t->event.parent_pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    t->event.parent_tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    t->event.cookie = 0;
    t->remaining = 2;
    int rc = clone_observer_before(&t->event);
    if (rc) {
        raw_syscall(__NR_munmap, mem, TRANSACTION_BYTES, 0, 0, 0, 0);
        return rc < 0 ? rc : -EINVAL;
    }
    return mem;
}

struct clone_return clone_notify_finish(void *transaction, long result)
{
    struct clone_transaction *t = transaction;
    struct clone_return saved = t->saved;
    unsigned long flags = t->event.flags;
    clone_observer_finish(&t->event, result);
    /* Separate VMs each unmap their own inherited mapping. CLONE_VM callers
     * must wait for both returning contexts before unmapping shared storage.
     * A child dying before notification can strand a mapping: no FD policy is
     * enabled until abnormal-exit and cancellation lifecycle is addressed. */
    if (result < 0 || !(flags & CLONE_VM) ||
        __atomic_sub_fetch(&t->remaining, 1, __ATOMIC_ACQ_REL) == 0)
        raw_syscall(__NR_munmap, (long)t, TRANSACTION_BYTES, 0, 0, 0, 0);
    return saved;
}
