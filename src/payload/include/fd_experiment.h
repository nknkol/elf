/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_EXPERIMENT_H
#define ELF_FD_EXPERIMENT_H
/* Private fork/bounded vfork FD experiment with optional path mutation guard;
 * NOT a complete filesystem isolation mode. */
#include <stddef.h>
#include <stdbool.h>
/* Partial path mutation guard only; disabled in observation/legacy mode. */
int fd_experiment_check_path_mutation(size_t mount, bool known);
long fd_experiment_scratch_alloc(size_t);
void fd_experiment_scratch_free(void *,size_t);
/* Query selector 6: observed policy decision for mount=a[2], operation=a[3].
 * ENODATA without observation config. Does not authorize or intercept IO. */
#define PR_ELF_FD_QUERY 0x46445452
long fd_experiment_export(void);
long fd_experiment_dispatch(long number,long args[6]);
#endif
