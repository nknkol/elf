/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PROOT_BINDING_CORE_H
#define PROOT_BINDING_CORE_H
#include "path/path_types.h"
/* Inputs are initialized, canonical absolute prefixes (no trailing slash
 * except /). No allocation, filesystem access, ptrace or talloc here. */
bool binding_matches_core(const char *root, Side, const char *prefix, const char *path);
int binding_replace_core(char path[PATH_MAX], const char *from, const char *to);

typedef struct { const char *guest; const char *host; } PathBinding;
typedef struct {
    const char *root;
    const PathBinding *entries;
    size_t count;
} BindingTable;
/* Validate once before publishing an immutable table. Caller owns strings.
 * This validates spelling only; symlinks/existence/glue require host setup.
 * Duplicate guest destinations: last entry wins. Most-specific prefix wins.
 */
int binding_table_validate(const BindingTable *);
/* Stable within one immutable table: 0=root, entry index+1=bind. */
int binding_table_mount_id(const BindingTable *, const char *, size_t *);
int binding_table_map(const BindingTable *, Side, const char *, char [PATH_MAX]);
#endif
