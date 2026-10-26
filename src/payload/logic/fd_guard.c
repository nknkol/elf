/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "fd_guard.h"
_Static_assert(__atomic_always_lock_free(8,0), "FD guard requires lock-free 64-bit atomics");
int fd_guard_enter(struct fd_guard *g,long tid,struct fd_guard_lease *lease)
{
    if (!g || !lease || tid<=0 || (unsigned long)tid>UINT32_MAX) return -EINVAL;
    uint64_t old=__atomic_load_n(&g->state,__ATOMIC_ACQUIRE);
    uint32_t owner=(uint32_t)old;
    if (owner) return owner==(uint32_t)tid ? -EDEADLK : -EAGAIN;
    uint64_t generation=old>>32;
    if (generation==UINT32_MAX) return -EOVERFLOW;
    uint64_t next=((generation+1)<<32)|(uint32_t)tid;
    if (!__atomic_compare_exchange_n(&g->state,&old,next,0,
                                     __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return (uint32_t)old==(uint32_t)tid ? -EDEADLK : -EAGAIN;
    lease->token=next;
    return 0;
}
int fd_guard_leave(struct fd_guard *g,struct fd_guard_lease lease)
{
    if (!g || !(uint32_t)lease.token || !(lease.token>>32)) return -EINVAL;
    uint64_t expected=lease.token;
    return __atomic_compare_exchange_n(&g->state,&expected,lease.token&~UINT64_C(0xffffffff),
                                       0,__ATOMIC_RELEASE,__ATOMIC_RELAXED) ? 0 : -ESTALE;
}
