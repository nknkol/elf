/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Rules protecting the loader-run process itself, shared by the loader
 * (initial images) and the payload (the guest's own memory calls). */
#ifndef INTEGRITY_H
#define INTEGRITY_H
#include <stddef.h>
#include <stdint.h>

/* With the seccomp backstop no memory may be writable and executable at
 * once: code written there after mapping is never hooked. (HongMeng does
 * not run syscalls issued from anonymous RWX pages at all, they fail with
 * ENOENT; the rule matters for kernels that do.) */
static inline int integrity_wx(int prot)
{
    return (prot & 6) == 6; /* PROT_WRITE | PROT_EXEC */
}

/* Payload: decides a guest call that would harm the process itself, with
 * *result set; 0 lets it go on. EPERM (as for mseal'ed memory) when a
 * memory call would unmap, remap, reprotect or discard the loader, the
 * payload or a stub island; EACCES for a W+X mapping under the backstop;
 * a SIGSYS rt_sigaction under the backstop is answered without installing
 * anything (the loader's handler stays). */
int integrity_check(long number, const long a[6], long *result);
#endif
