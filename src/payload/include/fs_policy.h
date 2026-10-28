/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FS_POLICY_H
#define ELF_FS_POLICY_H
#include <stddef.h>
#include <stdbool.h>
/* Immutable permissions indexed by binding_table_mount_id: root=0, bind=i+1.
 * The FD experiment uses this for diagnostics and an opt-in path mutation
 * guard plus selected FD mutations; full filesystem isolation is not enforced.
 * Caller must supply authenticated provenance in THIS policy/table incarnation,
 * after symlink resolution. Unknown origins and imported exec state are no grant.
 * No host path lookup, allocation, file IO or FD ownership lives here. */
enum fs_access { FS_DENY, FS_READ_ONLY, FS_READ_WRITE };
enum fs_operation { FS_OBSERVE, FS_MUTATE };
struct fs_policy {
    const enum fs_access *mounts;
    size_t count;
};
/* Validate before immutable publication; require exactly root + bind count. */
int fs_policy_validate(const struct fs_policy *, size_t bindings);
int fs_policy_check(const struct fs_policy *, size_t mount, bool known,
                    enum fs_operation);
/* rename/link namespace mutation: both ends must allow mutation and refer to
 * the same virtual mount. Callers resolve operands using their syscall-specific
 * follow/no-follow rules. This does not implement copy, rename or link itself. */
int fs_policy_check_pair(const struct fs_policy *, size_t source, bool source_known,
                         size_t target, bool target_known);
#endif
