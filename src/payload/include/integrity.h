/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Rules protecting the loader-run process itself from the guest's own
 * memory calls. Writable+executable memory needs no rule: HongMeng does not
 * run syscalls issued from anonymous RWX pages (ENOENT), and elsewhere the
 * seccomp backstop traps them like any unhooked call. */
#ifndef INTEGRITY_H
#define INTEGRITY_H
#include <stddef.h>
#include <stdint.h>

/* Payload: decides a guest call that would harm the process itself, with
 * *result set; 0 lets it go on. EPERM (as for mseal'ed memory) when a
 * memory call would unmap, remap, reprotect or discard the loader, the
 * payload or a stub island; a SIGSYS rt_sigaction under the backstop is
 * answered without installing anything (the loader's handler stays). */
int integrity_check(long number, const long a[6], long *result);
#endif
