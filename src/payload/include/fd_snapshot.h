/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_SNAPSHOT_H
#define ELF_FD_SNAPSHOT_H
#include "fd_table.h"

/* Version 1: little-endian uint64 words, no native pointers or padding.
 * Header: magic, version, serial, live-count. Entries: fd, cloexec (0),
 * generation, description, mount_id, access. Only exec-surviving FDs exported.
 * Storage need not be aligned and must not overlap table storage.
 * All calls require exclusive table access.
 * This format is not authenticated. Never accept guest-supplied metadata as
 * permission authority merely because parsing or memfd sealing succeeds. */
#define FD_SNAPSHOT_HEADER_BYTES 32u
#define FD_SNAPSHOT_ENTRY_BYTES 48u
int fd_snapshot_size(const struct fd_table *, size_t *bytes);
/* Short buffer returns ENOSPC without changing buffer, table, or *written. */
int fd_snapshot_export(const struct fd_table *, void *buffer, size_t capacity,
                       size_t *written);
/* Destination must be freshly initialized and empty. Validate the entire
 * immutable buffer before publication; all errors leave destination unchanged.
 * Caller must arrange FD ownership and verify that inherited FDs still exist.
 * Import does not touch kernel FDs or trust their provenance automatically. */
int fd_snapshot_import(struct fd_table *, const void *buffer, size_t bytes);
#endif
