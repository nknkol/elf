/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_HANDOFF_H
#define ELF_FD_HANDOFF_H
#include "fd_snapshot.h"
/* Returns a sealed CLOEXEC memfd, or negative errno. Caller owns the FD and
 * explicitly enables inheritance only immediately before its intended exec.
 * Failed exec must close the transport FD; original table is never modified.
 * Scratch/table storage must be disjoint, private to the caller during use. */
long fd_handoff_create(const struct fd_table *, void *scratch, size_t capacity);
/* Check seals, bounded-read then validate/import. Does not close transport FD.
 * Invalid/oversized snapshots leave the table unchanged (scratch may change).
 * Sealing ensures immutability, NOT authentication or permission authority. */
int fd_handoff_restore(struct fd_table *, int fd, void *scratch, size_t capacity);
#endif
