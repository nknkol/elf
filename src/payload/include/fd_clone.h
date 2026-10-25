/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_CLONE_H
#define ELF_FD_CLONE_H
#include "fd_table.h"
enum fd_clone_mode { FD_CLONE_COPY, FD_CLONE_SHARE };
/* Caller-owned, inherited shared storage. Source must be stable during prepare;
 * all table mutations still require external synchronization. A copied table
 * and its records must also be accessible in every inheriting VM. No allocation,
 * syscall, permission checks, or automatic inference from clone flags. */
struct fd_clone {
    struct fd_table *table;
    long child_tid;
};
/* Fresh, unpublished transaction only. Copy destination must be initialized,
 * empty and disjoint from source. SHARE requires a NULL destination. Errors do
 * not publish the transaction. Reserve registry/storage capacity before clone. */
int fd_clone_prepare(struct fd_clone *, struct fd_table *source,
                     struct fd_table *copy, enum fd_clone_mode);
/* Parent and child may publish in either order. Both must name the same kernel
 * child TID. No allocation after successful clone; duplicate publication is OK.
 * Caller must not publish a failed clone or a guessed/unknown child identity. */
int fd_clone_publish(struct fd_clone *, long child_tid);
/* NULL until identity publication, or for another identity. Returned table is
 * borrowed: retain transaction/table storage until readers and owners retire.
 * Cookie cleanup may retire the transaction, not a table adopted by the child.
 * TIDs are not durable identities: external registry must handle exit/reuse. */
struct fd_table *fd_clone_lookup(const struct fd_clone *, long child_tid);
#endif
