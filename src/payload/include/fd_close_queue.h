/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_CLOSE_QUEUE_H
#define ELF_FD_CLOSE_QUEUE_H
#include "fd_registry.h"
struct fd_close_ticket { size_t slot; uint64_t token; };
struct fd_close_slot {
    uint64_t state;
    struct fd_task_handle owner;
    struct fd_table *table;
    int fd;
    uint64_t generation;
};
struct fd_close_queue { struct fd_close_slot *slots; size_t capacity; };
/* Caller provides inherited shared storage. init is quiescent-only; prepare,
 * pending and drain require the same exclusion as the registry/table. Publish
 * alone is lock-free and can run while another task holds that exclusion.
 * All relevant adapters must check pending BEFORE operations on this FD and
 * before clone/exec/range transitions; this module does not intercept them. */
int fd_close_queue_init(struct fd_close_queue *,struct fd_close_slot *,size_t);
/* Pre-kernel reservation, captures generation and pins the owning task/table.
 * EBUSY on same-table/FD overlap; ENOSPC before syscall if no queue slot exists. */
int fd_close_prepare(struct fd_close_queue *,struct fd_registry *,
                     struct fd_task_handle,int fd,struct fd_close_ticket *);
/* Negative fd queries any pending operation on this table. */
int fd_close_pending(const struct fd_close_queue *,const struct fd_table *,int fd);
enum fd_close_effect { FD_CLOSE_KEEP, FD_CLOSE_REMOVE };
/* Does NOT infer close semantics from errno. Caller classifies the established
 * kernel effect; cancellation BEFORE kernel entry publishes KEEP. Uncertain or
 * interrupted results must remain reserved pending an explicit reconciliation.
 * No kernel syscall/retry, allocation or lock acquisition occurs here. */
int fd_close_publish(struct fd_close_queue *,struct fd_close_ticket,enum fd_close_effect);
/* Returns number drained; stale generations preserve the newer record. Keep
 * kernel return value unchanged. Table pin released only after metadata commit.
 * Unknown outcomes/abandoned reservations stay pinned; no automatic recovery.
 * Errors may follow earlier committed slots; never repeat their kernel calls.
 * All calls must use the registry associated with preparation. */
int fd_close_drain(struct fd_close_queue *,struct fd_registry *);
#endif
