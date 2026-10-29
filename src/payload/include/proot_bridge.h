/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PROOT_BRIDGE_H
#define PROOT_BRIDGE_H
#include <stddef.h>
#include <stdbool.h>
struct proot_path_context;
struct proot_open_origin;
int proot_resolve_exec_path(int dirfd, const char *path, bool follow,
                            char *guest, char *host, size_t capacity,
                            const struct proot_path_context *context);
size_t proot_bridge_scratch_size(void);
size_t proot_exec_scratch_size(void);
long proot_get_auxv(long args[6]);
long proot_execve(long number, long args[6]);
long proot_execve_context(long number, long args[6], const struct proot_path_context *context);
/* Restricted single-component, non-following O_PATH open beneath a dirfd. */
long proot_open_beneath(int dirfd, const char *path, unsigned long flags,
                       const struct proot_open_origin *anchor, struct proot_open_origin *origin);
/* Resolution observation, not an authorization grant. Known dirfd origins
 * and established cwd select the reverse mapping; unknown/imported anchors
 * stay unknown. Exec does not authenticate or restore cwd provenance. */
struct proot_open_origin { size_t mount_id; bool known; };
/* Re-derive a regular FD's unique current mount view from kernel identity.
 * No snapshot origin is accepted; ambiguous/unlinked/unmatched objects fail. */
int proot_revalidate_regular_fd(int fd, struct proot_open_origin *origin);
/* Same unique-view rule for the kernel cwd, never a stored cwd tag. */
int proot_revalidate_cwd(struct proot_open_origin *origin);
/* Read guard listing: EACCES for a hidden directory; hidden entries are
 * removed from each kernel batch. Only exact names are filtered, so d_off
 * stays the kernel cursor of the last returned record. */
long proot_getdents_visible(int fd, void *buffer, unsigned long count,
                            const struct proot_open_origin *anchor);
/* Rewrite a kernel-returned pathname AF_UNIX address (accept, getsockname,
 * getpeername) in guest terms, honoring the caller's buffer capacity and
 * reporting the full length like the kernel. Read guard: an unmappable or
 * hidden name is reported as unnamed. */
void proot_socket_name(long number, long fd, void *address, unsigned *length,
                       unsigned capacity);
long proot_openat(long args[6], const struct proot_open_origin *anchor,
                  struct proot_open_origin *origin);
long proot_cwd(long number, long args[6], const struct proot_open_origin *anchor,
               struct proot_open_origin *origin);
/* Immutable per-call observations for cwd and up to two directory operands. */
struct proot_path_context {
    struct proot_open_origin cwd, directory[2];
    int fd[2];
};
long proot_context_syscall(long number, long args[6], const struct proot_path_context *context);
int proot_handles_syscall(long number);
long proot_syscall(long number, long args[6]);
#endif
