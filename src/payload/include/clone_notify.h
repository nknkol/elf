/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_CLONE_NOTIFY_H
#define ELF_CLONE_NOTIFY_H
#include <stdint.h>
#define CLONE_NOTIFY_CAPACITY 64
#define CLONE_CLEANUP_PARENT_ABANDONED 1u
#define CLONE_CLEANUP_CHILD_ABANDONED 2u
#define CLONE_CLEANUP_REJECTED 4u
struct clone_event {
    unsigned long flags;
    long parent_pid, parent_tid;
    void *cookie;
};
/* Observer seam, not FD tracking yet. before returns 0 or negative errno.
 * finish runs once per returning parent/child (once on kernel error).
 * A child may notify first. No libc/TLS dependencies or locks spanning clone.
 * Event storage survives fork and is valid only within these callbacks.
 * before may set cookie only; flags and parent identity remain immutable.
 * Once before returns (including rejection), cookie ownership passes to the
 * transaction until cleanup. finish must not free it. Partial allocation before
 * a nonlocal exit from before remains the observer's responsibility. */
int clone_observer_before(struct clone_event *event);
void clone_observer_finish(const struct clone_event *event, long result);
/* Exactly one invocation after both roles and all readers complete, or after
 * before rejects. reasons is a CLONE_CLEANUP_* mask (zero for normal completion
 * and kernel failure). Reaper cleanup may run in any inheriting task/VM. A cookie
 * dereferenced by cleanup must reference inherited shared storage or a stable
 * arena handle, never private or post-fork-only mappings. Parent-only cookies
 * may reference private inherited storage only if child finish and cleanup
 * never dereference it; that storage must survive the parent finish callback.
 * This callback retires shared metadata, not process-local FDs/mappings. It must be nonblocking and
 * reentrant, with no libc/TLS dependency. A finalizer that dies/escapes strands
 * its slot; cleanup is never retried because its side effects may have occurred.
 * Unknown-child transactions are retained, not cleaned speculatively. */
void clone_observer_cleanup(const struct clone_event *event, unsigned reasons);
/* Reclaim missing returns only when kernel tgkill(..., 0) confirms ESRCH.
 * Returns number of abandoned parent/child roles completed. Unknown child
 * identity, interrupted initialization and abandoned reaper pins cannot yet
 * be reclaimed. Pool exhaustion returns EAGAIN, never untracked passthrough. */
unsigned clone_notify_reap(void);
long clone_notify_prepare(unsigned long saved_x9, unsigned long continuation,
                          unsigned long flags);
/* AAPCS64 returns the two words in x0/x1. */
struct clone_return { unsigned long saved_x9, continuation; };
struct clone_return clone_notify_finish(void *transaction, long result);
#endif
