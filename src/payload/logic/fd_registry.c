/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <stdint.h>
#include "fd_registry.h"
#define RESERVED 1u
#define LIVE 2u
int fd_registry_init(struct fd_registry *r, struct fd_task_slot *tasks, size_t nt,
                     struct fd_table_slot *tables, size_t nb,
                     struct fd_record *records, size_t capacity)
{
    if (!r || !tasks || !tables || !records || !nt || !nb || !capacity ||
        nb > SIZE_MAX / capacity || nb * capacity > SIZE_MAX / sizeof(*records))
        return -EINVAL;
    *r = (struct fd_registry){tasks,tables,nt,nb,0};
    for (size_t i=0;i<nt;i++) tasks[i]=(struct fd_task_slot){0};
    for (size_t i=0;i<nb;i++) {
        tables[i].owners=0;
        fd_table_init(&tables[i].table,records+i*capacity,capacity);
    }
    return 0;
}
static struct fd_task_slot *resolve(struct fd_registry *r, struct fd_task_handle h)
{
    if (!r || h.slot>=r->task_count || !h.generation) return 0;
    struct fd_task_slot *t=&r->tasks[h.slot];
    return t->state && t->generation==h.generation ? t : 0;
}
struct fd_table *fd_registry_table(struct fd_registry *r, struct fd_task_handle h)
{
    struct fd_task_slot *t=resolve(r,h);
    return t ? &r->tables[t->table_slot].table : 0;
}
static int reserve(struct fd_registry *r, struct fd_task_slot *parent,
                   enum fd_clone_mode mode, struct fd_task_handle *out)
{
    if (!r || !out) return -EINVAL;
    if (r->serial==UINT64_MAX) return -EOVERFLOW;
    size_t task=0, table=0;
    while (task<r->task_count && r->tasks[task].state) task++;
    if (task==r->task_count) return -ENOSPC;
    if (parent && mode==FD_CLONE_SHARE) table=parent->table_slot;
    else {
        while (table<r->table_count && r->tables[table].owners) table++;
        if (table==r->table_count) return -ENOSPC;
    }
    struct fd_table_slot *b=&r->tables[table];
    if (!b->owners) fd_table_init(&b->table,b->table.slots,b->table.capacity);
    struct fd_clone prepared={0};
    if (parent) {
        int rc=fd_clone_prepare(&prepared,&r->tables[parent->table_slot].table,
                                mode==FD_CLONE_COPY?&b->table:0,mode);
        if (rc) return rc;
    } else prepared.table=&b->table;
    r->tasks[task]=(struct fd_task_slot){.generation=++r->serial,.state=RESERVED,
        .table_slot=table,.clone=prepared};
    b->owners++;
    *out=(struct fd_task_handle){task,r->serial};
    return 0;
}
int fd_registry_create(struct fd_registry *r, struct fd_task_handle *out)
{ return reserve(r,0,FD_CLONE_COPY,out); }
int fd_registry_clone(struct fd_registry *r, struct fd_task_handle h,
                      enum fd_clone_mode mode, struct fd_task_handle *out)
{
    if (mode!=FD_CLONE_COPY && mode!=FD_CLONE_SHARE) return -EINVAL;
    struct fd_task_slot *parent=resolve(r,h);
    if (!parent || parent->state!=LIVE) return -ESTALE;
    return reserve(r,parent,mode,out);
}
int fd_registry_publish(struct fd_registry *r, struct fd_task_handle h,long tid)
{
    if (tid<=0) return -EINVAL;
    struct fd_task_slot *t=resolve(r,h);
    if (!t) return -ESTALE;
    for (size_t i=0;i<r->task_count;i++)
        if (i!=h.slot && r->tasks[i].state==LIVE &&
            r->tasks[i].clone.child_tid==tid) return -EEXIST;
    int rc=fd_clone_publish(&t->clone,tid);
    if (!rc) t->state=LIVE;
    return rc;
}
int fd_registry_find(struct fd_registry *r,long tid,struct fd_task_handle *out)
{
    if (!r || !out || tid<=0) return -EINVAL;
    for (size_t i=0;i<r->task_count;i++)
        if (r->tasks[i].state==LIVE && r->tasks[i].clone.child_tid==tid) {
            *out=(struct fd_task_handle){i,r->tasks[i].generation};return 0;
        }
    return -ENOENT;
}
static int release(struct fd_registry *r,struct fd_task_handle h,unsigned state)
{
    struct fd_task_slot *t=resolve(r,h);
    if (!t) return -ESTALE;
    if (t->state!=state || t->pending) return -EBUSY;
    r->tables[t->table_slot].owners--;
    t->state=0;
    return 0;
}
int fd_registry_cancel(struct fd_registry *r,struct fd_task_handle h)
{ return release(r,h,RESERVED); }
int fd_registry_retire(struct fd_registry *r,struct fd_task_handle h)
{ return release(r,h,LIVE); }

int fd_registry_pin(struct fd_registry *r,struct fd_task_handle h)
{
    struct fd_task_slot *t=resolve(r,h);
    if (!t || t->state!=LIVE) return -ESTALE;
    if (t->pending==SIZE_MAX) return -EOVERFLOW;
    t->pending++;
    return 0;
}
int fd_registry_unpin(struct fd_registry *r,struct fd_task_handle h)
{
    struct fd_task_slot *t=resolve(r,h);
    if (!t) return -ESTALE;
    if (!t->pending) return -EINVAL;
    t->pending--;
    return 0;
}
