/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PROOT_BRIDGE_H
#define PROOT_BRIDGE_H
#include <stddef.h>
#include <stdbool.h>
int proot_resolve_exec_path(int dirfd, const char *path, bool follow,
                            char *guest, char *host, size_t capacity);
size_t proot_bridge_scratch_size(void);
size_t proot_exec_scratch_size(void);
long proot_get_auxv(long args[6]);
long proot_execve(long number, long args[6]);
/* Restricted single-component, non-following O_PATH open beneath a dirfd. */
long proot_open_beneath(int dirfd, const char *path, unsigned long flags);
/* Resolution observation, not an authorization grant. Known dirfd origins
 * and established cwd select the reverse mapping; unknown/imported anchors
 * stay unknown. Exec does not authenticate or restore cwd provenance. */
struct proot_open_origin { size_t mount_id; bool known; };
long proot_openat(long args[6], const struct proot_open_origin *anchor,
                  struct proot_open_origin *origin);
long proot_cwd(long number, long args[6], const struct proot_open_origin *anchor,
               struct proot_open_origin *origin);
int proot_handles_syscall(long number);
long proot_syscall(long number, long args[6]);
#endif
