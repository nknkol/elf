/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PROOT_RESOLVE_CORE_H
#define PROOT_RESOLVE_CORE_H
#include "path/canon_core.h"
/* cwd is a guest absolute path, owned by the caller. dirfd_guest must resolve
 * the current FD object, not a cached pathname from its original open().
 * guest_to_host maps a canonical guest path. No allocation or ptrace needed.
 * No extension dispatch here; the legacy translate_path keeps that behavior.
 */
typedef struct {
    PathContext path;
    const char *cwd;
    int (*dirfd_guest)(void *, int, char [PATH_MAX]);
    int (*guest_to_host)(void *, const char *, char [PATH_MAX]);
    /* Optional base and joined-path scratch (two PATH_MAX buffers). */
    char (*scratch)[PATH_MAX];
} PathResolver;
int resolve_path_core(PathResolver *, int, const char *, bool,
                      char [PATH_MAX], char [PATH_MAX]);
#endif
