/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HOST_SYSCALL_H
#define HOST_SYSCALL_H
/* A syscall on host paths: with --isolate the calls of broker_proto.h are
 * executed by the broker process, everything else (and every call without
 * --isolate) goes to the kernel directly. */
long host_syscall(long nr, long a0, long a1, long a2, long a3, long a4, long a5);
/* Guest calls the guest filter refuses that the bridge does not see (UNIX
 * socket creation, FD xattr changes) go to the broker; a few are adjusted
 * to a form the filter allows. 1 with *result when handled. */
int broker_route(long nr, long a[6], long *result);
/* Isolation mode, this thread: following requests carry BROKER_STRICT (the
 * broker refuses to traverse any symlink: optimistic lexical resolution). */
void broker_strict(int on);
/* The symlink the last strict refusal met (PATH_MAX buffers); 0 if none. */
int broker_link_report(char *path, char *target);
/* Isolation mode: the guest cannot close or replace the payload's FDs. */
int broker_fd_guard(long nr, const long a[6], long *result);
#endif
