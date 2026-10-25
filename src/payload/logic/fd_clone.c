/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "fd_clone.h"
int fd_clone_prepare(struct fd_clone *t, struct fd_table *source,
                     struct fd_table *copy, enum fd_clone_mode mode)
{
    if (!t || !source || (mode != FD_CLONE_COPY && mode != FD_CLONE_SHARE))
        return -EINVAL;
    if (mode == FD_CLONE_COPY) {
        if (!copy) return -EINVAL;
        int rc = fd_table_copy(copy, source);
        if (rc) return rc;
    } else if (copy) return -EINVAL;
    t->table = mode == FD_CLONE_COPY ? copy : source;
    __atomic_store_n(&t->child_tid, 0, __ATOMIC_RELEASE);
    return 0;
}
int fd_clone_publish(struct fd_clone *t, long child_tid)
{
    if (!t || !t->table || child_tid <= 0) return -EINVAL;
    long expected = 0;
    if (__atomic_compare_exchange_n(&t->child_tid, &expected, child_tid, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return 0;
    return expected == child_tid ? 0 : -EEXIST;
}
struct fd_table *fd_clone_lookup(const struct fd_clone *t, long child_tid)
{
    if (!t || child_tid <= 0 ||
        __atomic_load_n(&t->child_tid, __ATOMIC_ACQUIRE) != child_tid) return 0;
    return t->table;
}
