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

/* Component-wise strict prefix: "/a" contains "/a/b" but not "/ab". */
static bool strict_ancestor(const char *path, const char *descendant)
{
    size_t length = 0;
    while (path[length] && path[length] == descendant[length]) length++;
    if (path[length]) return false;
    if (length == 1 && path[0] == '/') return descendant[1] != 0;
    return descendant[length] == '/' && descendant[length + 1];
}

enum fs_visibility fs_policy_visibility(const struct fs_policy *p, size_t mount,
                                        const char *guest, const char *const *exposed,
                                        size_t count)
{
    if (!p || !p->mounts || mount >= p->count || !guest || guest[0] != '/')
        return FS_HIDDEN;
    if (p->mounts[mount] == FS_READ_ONLY || p->mounts[mount] == FS_READ_WRITE)
        return FS_VISIBLE;
    if (p->mounts[mount] != FS_DENY) return FS_HIDDEN;
    for (size_t i = 0; exposed && i < count; i++)
        if (exposed[i] && strict_ancestor(guest, exposed[i])) return FS_TRAVERSE;
    return FS_HIDDEN;
}
