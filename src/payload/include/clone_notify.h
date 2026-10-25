/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_CLONE_NOTIFY_H
#define ELF_CLONE_NOTIFY_H
#include <stdint.h>
struct clone_event {
    unsigned long flags;
    long parent_pid, parent_tid;
    void *cookie;
};
/* Observer seam, not FD tracking yet. before returns 0 or negative errno.
 * finish runs once per returning parent/child (once on kernel error).
 * A child may notify first. No libc/TLS dependencies or locks spanning clone.
 * Event storage survives fork and is valid only within these callbacks. */
int clone_observer_before(struct clone_event *event);
void clone_observer_finish(const struct clone_event *event, long result);
long clone_notify_prepare(unsigned long saved_x9, unsigned long continuation,
                          unsigned long flags);
/* AAPCS64 returns the two words in x0/x1. */
struct clone_return { unsigned long saved_x9, continuation; };
struct clone_return clone_notify_finish(void *transaction, long result);
#endif
