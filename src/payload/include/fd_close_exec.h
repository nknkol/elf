/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_CLOSE_EXEC_H
#define ELF_FD_CLOSE_EXEC_H
#include "fd_close_queue.h"
#include "fd_guard.h"
/* Execute one close through guard -> reservation -> kernel -> publication ->
 * best-effort drain. Existing registry/queue/guard must share a lifetime and
 * every other FD adapter must cooperate with pending checks. No allocations.
 * Return the exact kernel result once invoked; preflight errors never invoke
 * close (negative FD is rejected with EBADF). owner must match the actual
 * current TID registration. bookkeeping is required: 0 committed, EAGAIN/EDEADLK deferred after
 * publication, EINPROGRESS unknown kernel effect (all stored as negative errno).
 * Other negative bookkeeping errors require reconciliation, not kernel retry.
 * Only 0 and EBADF establish removal here. No assumptions about EINTR or other
 * host errors; their reservations stay pinned. This is NOT default interception
 * or permission enforcement, and does not bypass registry on any error. */
long fd_close_execute(struct fd_close_queue *,struct fd_registry *,struct fd_guard *,
                      struct fd_task_handle,int fd,int *bookkeeping);
#endif
