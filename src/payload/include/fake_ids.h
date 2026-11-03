#ifndef FAKE_IDS_H
#define FAKE_IDS_H

#include <stdint.h>

/* Handles get*id/set*id/setgroups, capget/capset and the prctl capability
 * options; returns 1 with *result set, else 0. */
int fake_ids_syscall(long number, long a[6], long *result);
/* Whether the effective set holds capability cap (CAP_CHOWN 0, CAP_FOWNER 3). */
int fake_ids_capable(int cap);
/* Owner reported for the caller's own files (saved uid/gid, as PRoot). */
uint32_t fake_ids_owner(int group);
/* Supplementary groups into out; returns their count. */
int fake_ids_groups(uint32_t out[32]);
/* Reported owner of a host uid/gid: the caller's own become the saved id. */
uint32_t fake_ids_reported_owner(uint32_t id, int group);
/* stat/fstat/newfstatat/statx result: the caller's own files (its real ids
 * and the owners of the root and bind directories) show the fake owner. */
void fake_ids_stat_owner(long number, const long *args);
/* Whether a host uid (group 0) or gid is one of the user's own. */
int fake_ids_host_owned(uint32_t id, int group);
/* Effective and file-system ids (group 0: uid, 1: gid). */
uint32_t fake_ids_effective(int group);
uint32_t fake_ids_fs(int group);
/* r/e/s/fs uid then gid; returns whether any differs from root. */
int fake_ids_current(uint32_t out[8]);

#endif /* FAKE_IDS_H */
