/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_EXPERIMENT_H
#define ELF_FD_EXPERIMENT_H
/* Private fork/bounded vfork FD experiment with optional path/FD mutation guards
 * and read/visibility guard; NOT a complete filesystem isolation mode. */
#include <stddef.h>
#include <stdbool.h>
#include "config.h"
#include "fs_policy.h"
/* Partial path mutation guard only; disabled in observation/legacy mode. */
int fd_experiment_check_path_mutation(size_t mount, bool known);
/* Validated root+bind access vector; ENODATA without a configured policy. */
int fd_experiment_mount_access(enum fs_access access[CONFIG_MAX_BINDS + 1], size_t *count);
long fd_experiment_scratch_alloc(size_t);
void fd_experiment_scratch_free(void *,size_t);
/* Query selector 6: observed policy decision for mount=a[2], operation=a[3].
 * ENODATA without observation config. Does not authorize or intercept IO. */
#define PR_ELF_FD_QUERY 0x46445452
long fd_experiment_export(void);
long fd_experiment_dispatch(long number,long args[6]);
#endif
