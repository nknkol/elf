/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "fs_policy.h"

int fs_policy_validate(const struct fs_policy *p, size_t bindings)
{
    if (!p || !p->mounts || bindings == (size_t)-1 || p->count != bindings + 1)
        return -EINVAL;
    for (size_t i = 0; i < p->count; i++)
        if (p->mounts[i] != FS_DENY && p->mounts[i] != FS_READ_ONLY &&
            p->mounts[i] != FS_READ_WRITE)
            return -EINVAL;
    return 0;
}

int fs_policy_check(const struct fs_policy *p, size_t mount, bool known,
                    enum fs_operation operation)
{
    if (operation != FS_OBSERVE && operation != FS_MUTATE)
        return -EINVAL;
    if (!p || !p->mounts || !known || mount >= p->count)
        return -EACCES;
    switch (p->mounts[mount]) {
    case FS_READ_WRITE: return 0;
    case FS_READ_ONLY: return operation == FS_MUTATE ? -EROFS : 0;
    default: return -EACCES;
    }
}

int fs_policy_check_pair(const struct fs_policy *p, size_t source, bool source_known,
                         size_t target, bool target_known)
{
    int rc = fs_policy_check(p, source, source_known, FS_MUTATE);
    if (rc < 0) return rc;
    rc = fs_policy_check(p, target, target_known, FS_MUTATE);
    if (rc < 0) return rc;
    return source == target ? 0 : -EXDEV;
}
