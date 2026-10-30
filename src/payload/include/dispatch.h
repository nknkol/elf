/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef DISPATCH_H
#define DISPATCH_H
/* Every guest syscall not decided earlier (integrity checks, the guarded
 * runtime): PRoot semantics, then native. */
long dispatch_syscall(long number, long args[6]);
#endif
