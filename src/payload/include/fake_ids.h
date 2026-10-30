#ifndef FAKE_IDS_H
#define FAKE_IDS_H

#include <stdint.h>

/* Handles get*id/set*id/setgroups; returns 1 with *result set, else 0. */
int fake_ids_syscall(long number, long a[6], long *result);
/* Fake effective uid 0: the kernel's EPERM on chown is reported as success. */
int fake_ids_privileged(void);
/* Owner reported for the caller's own files (saved uid/gid, as PRoot). */
uint32_t fake_ids_owner(int group);
/* r/e/s/fs uid then gid; returns whether any differs from root. */
int fake_ids_current(uint32_t out[8]);

#endif /* FAKE_IDS_H */
