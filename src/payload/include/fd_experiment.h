/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_EXPERIMENT_H
#define ELF_FD_EXPERIMENT_H
/* Compile-time, private fork and bounded vfork metadata experiment; NOT a permissions mode. */
#include <stddef.h>
void fd_experiment_exec_scratch(void *,size_t);
#define PR_ELF_FD_QUERY 0x46445452
long fd_experiment_export(void);
long fd_experiment_dispatch(long number,long args[6]);
#endif
