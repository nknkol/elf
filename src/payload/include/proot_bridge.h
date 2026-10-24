/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PROOT_BRIDGE_H
#define PROOT_BRIDGE_H
#include <stddef.h>
#include <stdbool.h>
int proot_resolve_exec_path(int dirfd, const char *path, bool follow,
                            char *guest, char *host, size_t capacity);
long proot_execve(long number, long args[6]);
int proot_handles_syscall(long number);
long proot_syscall(long number, long args[6]);
#endif
