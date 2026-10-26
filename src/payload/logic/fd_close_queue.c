/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <limits.h>
#include "fd_close_queue.h"
#define RESERVED 1u
#define KEEP 2u
#define REMOVE 3u
#define UNKNOWN 4u
#define PHASE 7u
_Static_assert(__atomic_always_lock_free(8,0), "close publication requires lock-free atomics");
int fd_close_queue_init(struct fd_close_queue *q,struct fd_close_slot *slots,size_t n)
{
    if (!q || !slots || !n || n>INT_MAX) return -EINVAL;
    *q=(struct fd_close_queue){slots,n};
    for(size_t i=0;i<n;i++)slots[i]=(struct fd_close_slot){0};
    return 0;
}
int fd_close_pending(const struct fd_close_queue *q,const struct fd_table *t,int fd)
{
    for(size_t i=0;i<q->capacity;i++)
        if ((__atomic_load_n(&q->slots[i].state,__ATOMIC_ACQUIRE)&PHASE) &&
            q->slots[i].table==t && (fd<0 || q->slots[i].fd==fd)) return 1;
    return 0;
}
int fd_close_prepare(struct fd_close_queue *q,struct fd_registry *r,
                     struct fd_task_handle owner,int fd,struct fd_close_ticket *out)
{
    if (!q || !r || !out || fd<0) return -EINVAL;
    struct fd_table *t=fd_registry_table(r,owner);
    if (!t) return -ESTALE;
    if (fd_close_pending(q,t,fd)) return -EBUSY;
    size_t i;
    uint64_t state=0;
    int exhausted=0;
    for(i=0;i<q->capacity;i++) {
        state=__atomic_load_n(&q->slots[i].state,__ATOMIC_ACQUIRE);
        if (state&PHASE) continue;
        if ((state>>3)==(UINT64_MAX>>3)) { exhausted=1;continue; }
        break;
    }
    if (i==q->capacity) return exhausted ? -EOVERFLOW : -ENOSPC;
    int rc=fd_registry_pin(r,owner);
    if (rc) return rc;
    struct fd_close_slot *s=&q->slots[i];
    const struct fd_record *record=fd_table_get(t,fd);
    s->owner=owner;s->table=t;s->fd=fd;s->generation=record?record->generation:0;
    uint64_t token=state+8+RESERVED;
    __atomic_store_n(&s->state,token,__ATOMIC_RELEASE);
    *out=(struct fd_close_ticket){i,token};
    return 0;
}
int fd_close_publish(struct fd_close_queue *q,struct fd_close_ticket ticket,enum fd_close_effect effect)
{
    if (!q || ticket.slot>=q->capacity || (ticket.token&PHASE)!=RESERVED ||
        !(ticket.token>>3) || (effect!=FD_CLOSE_KEEP && effect!=FD_CLOSE_REMOVE && effect!=FD_CLOSE_UNKNOWN)) return -EINVAL;
    uint64_t expected=ticket.token;
    uint64_t ready=(ticket.token&~UINT64_C(7))|(effect==FD_CLOSE_KEEP?KEEP:effect==FD_CLOSE_REMOVE?REMOVE:UNKNOWN);
    return __atomic_compare_exchange_n(&q->slots[ticket.slot].state,&expected,ready,0,
                                       __ATOMIC_RELEASE,__ATOMIC_RELAXED) ? 0 : -ESTALE;
}
int fd_close_forget_unknown(struct fd_close_queue *q,const struct fd_table *table,int fd)
{
    if (!q || !table || fd<0) return -EINVAL;
    for (size_t i=0;i<q->capacity;i++) {
        struct fd_close_slot *s=&q->slots[i];
        uint64_t state=__atomic_load_n(&s->state,__ATOMIC_ACQUIRE);
        unsigned phase=state&PHASE;
        if (!phase || s->table!=table || s->fd!=fd) continue;
        if (phase==RESERVED) return -EINPROGRESS;
        if (phase!=UNKNOWN) return -EALREADY;
        /* Published outcomes are immutable; only guarded reconciliation/drain
         * changes this state. A duplicate producer CAS cannot overwrite it. */
        __atomic_store_n(&s->state,(state&~UINT64_C(7))|REMOVE,__ATOMIC_RELEASE);
        return 0;
    }
    return -ENOENT;
}

int fd_close_drain(struct fd_close_queue *q,struct fd_registry *r)
{
    if (!q || !r) return -EINVAL;
    int count=0;
    for(size_t i=0;i<q->capacity;i++) {
        struct fd_close_slot *s=&q->slots[i];
        uint64_t state=__atomic_load_n(&s->state,__ATOMIC_ACQUIRE);
        unsigned phase=state&PHASE;
        if (phase!=KEEP && phase!=REMOVE) continue;
        if (fd_registry_table(r,s->owner)!=s->table) return -ESTALE;
        if (phase==REMOVE) {
            int rc=fd_table_close_generation(s->table,s->fd,s->generation);
            if (rc && rc!=-ESTALE) return rc;
        }
        int rc=fd_registry_unpin(r,s->owner);
        if (rc) return rc;
        __atomic_store_n(&s->state,state&~UINT64_C(7),__ATOMIC_RELEASE);
        count++;
    }
    return count;
}
