/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ASYNC_IO_H
#define ASYNC_IO_H
/* Signal-driven I/O on HarmonyOS: sockets refuse FIOASYNC (ENOTTY), O_ASYNC
 * (EINVAL, or ignored on TCP) and F_SETOWN (EINVAL); pty masters likewise.
 * Programs that set it up and do not depend on the signal (nginx: the
 * master's channel to its workers) stop there. When the kernel refuses,
 * the setting is accepted and kept here, and F_GETFL, F_GETOWN,
 * F_GETOWN_EX and F_GETSIG read it back; no SIGIO is ever sent for it.
 * Returns 1 with *result when the call was handled; close and dup3 only
 * drop the number's settings (0). */
int async_io_syscall(long number, long a[6], long *result);
#endif
