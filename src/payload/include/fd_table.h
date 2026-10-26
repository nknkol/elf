/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_TABLE_H
#define ELF_FD_TABLE_H
#include <stddef.h>
#include <stdint.h>

/* Metadata only, not a syscall interceptor or a permission enforcement layer.
 * Caller supplies exclusive access, storage and successful kernel events.
 * Reserve capacity before publishing a new kernel FD in a future adapter.
 * Unknown provenance must never be interpreted as read/write permission. */
enum fd_access { FD_ACCESS_UNKNOWN, FD_ACCESS_RO, FD_ACCESS_RW };
struct fd_origin {
    uint64_t mount_id;
    enum fd_access access;
};
struct fd_record {
    int fd;                    /* -1 is unused */
    int cloexec;               /* descriptor flag, not open-file status */
    uint64_t generation;       /* changes on assignment, not F_SETFD */
    uint64_t description;      /* duplicates share it; 0 means unknown */
    struct fd_origin origin;
};
struct fd_table {
    struct fd_record *slots;
    size_t capacity;
    uint64_t serial;
};
int fd_table_init(struct fd_table *, struct fd_record *, size_t);
const struct fd_record *fd_table_get(const struct fd_table *, int fd);
/* Successful open/adoption. Distinct opens have distinct descriptions even
 * when host inode and mount match. All errors leave the table unchanged. */
int fd_table_open(struct fd_table *, int fd, struct fd_origin, int cloexec);
/* Successful dup/dup3/F_DUPFD. same-FD success is dup2's no-op. Unknown source
 * replaces destination provenance with unknown rather than keeping old rights. */
int fd_table_dup(struct fd_table *, int source, int target, int cloexec);
int fd_table_set_cloexec(struct fd_table *, int fd, int cloexec);
void fd_table_close(struct fd_table *, int fd);
/* Delayed removal after a separately established close/reconciliation outcome.
 * Capture the generation under exclusion before kernel entry (0 if untracked),
 * then reenter exclusion to commit. Matching records are removed; absent records
 * are already reconciled; a newer record returns ESTALE and is left unchanged.
 * This is metadata ordering protection, NOT an atomic check-and-close: callers
 * must separately prevent/reconcile reuse BEFORE the kernel close, retain the
 * same table incarnation, and classify kernel errors. Never retry kernel close
 * merely because metadata commit was delayed. ESTALE is bookkeeping status,
 * not a replacement for the kernel return value. Unknown provenance is no grant. */
int fd_table_close_generation(struct fd_table *, int fd, uint64_t generation);
/* Call only for a successfully applied range; UNSHARE is adapter-owned. */
int fd_table_range(struct fd_table *, unsigned first, unsigned last, int cloexec);
void fd_table_exec(struct fd_table *);
/* Snapshot into an initialized, empty table with disjoint storage. Used for
 * copied kernel FD tables; actual shared kernel tables require the SAME table.
 * Do not infer sharing solely from clone flags on this host. IDs are local
 * to a table lineage, not globally unique between independent fork branches. */
int fd_table_copy(struct fd_table *destination, const struct fd_table *source);
#endif
