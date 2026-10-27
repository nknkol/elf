/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PROOT_SCRATCH_H
#define PROOT_SCRATCH_H
#include <stddef.h>
#include <asm/unistd.h>
#ifdef FD_EXPERIMENT
#include "fd_experiment.h"
#define proot_scratch_alloc fd_experiment_scratch_alloc
#define proot_scratch_free fd_experiment_scratch_free
#else
extern long raw_syscall(long,long,long,long,long,long,long);
static inline long proot_scratch_alloc(size_t size)
{ return raw_syscall(__NR_mmap,0,size,3,0x22,-1,0); }
static inline void proot_scratch_free(void *p,size_t size)
{ raw_syscall(__NR_munmap,(long)p,size,0,0,0,0); }
#endif
#endif
