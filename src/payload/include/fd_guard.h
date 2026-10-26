/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_GUARD_H
#define ELF_FD_GUARD_H
#include <stdint.h>
/* Zero-initialize once in inherited shared storage before concurrent use.
 * Serializes short metadata sections only. Never hold across a syscall, clone,
 * callback, allocation or blocking work. Caller supplies the actual kernel TID.
 * No spinning, waiting, TLS or dead-owner reset; uncertainty must not unlock
 * partially modified metadata. All accesses to protected data must cooperate. */
struct fd_guard { uint64_t state; };
struct fd_guard_lease { uint64_t token; };
/* EDEADLK: same TID reentry. EAGAIN: contention. EOVERFLOW: generation exhausted.
 * Failure leaves lease untouched. Do not turn these failures into passthrough
 * in a permission mode. Post-syscall bookkeeping needs a separate protocol. */
int fd_guard_enter(struct fd_guard *, long tid, struct fd_guard_lease *);
/* Stale/duplicate release cannot unlock a newer lease, even with reused TID.
 * Caller must be the acquiring task; leases are not security capabilities. */
int fd_guard_leave(struct fd_guard *, struct fd_guard_lease);
#endif
