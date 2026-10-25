/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_CLONE_NOTIFY_H
#define ELF_CLONE_NOTIFY_H
#include <stdint.h>
#define CLONE_NOTIFY_CAPACITY 64
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
 * No cookie ownership or abandonment cleanup is provided yet: FD resources
 * must not be attached until their cancellation protocol is implemented. */
int clone_observer_before(struct clone_event *event);
void clone_observer_finish(const struct clone_event *event, long result);
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
