/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HOST_SYSCALL_H
#define HOST_SYSCALL_H
/* A syscall on host paths: with --isolate the calls of broker_proto.h are
 * executed by the broker process, everything else (and every call without
 * --isolate) goes to the kernel directly. */
long host_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
#endif
