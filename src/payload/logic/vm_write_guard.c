/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "vm_write_guard.h"
static int append(struct vm_write_guard *out, uintptr_t begin, uintptr_t end)
{
    if(begin==end)return 0;
    if(out->count==VM_WRITE_REGIONS)return -ENOSPC;
    out->regions[out->count++]=(struct vm_write_region){begin,end};
    return 0;
}
int vm_write_add(struct vm_write_guard *g, uintptr_t begin, uintptr_t end)
{
    if(!g || begin>=end || g->count>VM_WRITE_REGIONS)return -EINVAL;
    struct vm_write_guard next={0};
    bool inserted=false;
    for(size_t i=0;i<g->count;i++) {
        struct vm_write_region r=g->regions[i];
        int rc;
        if(r.end<begin)rc=append(&next,r.begin,r.end);
        else if(r.begin>end) {
            if(!inserted) {
                rc=append(&next,begin,end);if(rc)return rc;
                inserted=true;
            }
            rc=append(&next,r.begin,r.end);
        } else {
            if(r.begin<begin)begin=r.begin;
            if(r.end>end)end=r.end;
            continue;
        }
        if(rc)return rc;
    }
    if(!inserted) { int rc=append(&next,begin,end);if(rc)return rc; }
    *g=next;return 0;
}
int vm_write_remove(struct vm_write_guard *g, uintptr_t begin, uintptr_t end)
{
    if(!g || begin>=end || g->count>VM_WRITE_REGIONS)return -EINVAL;
    struct vm_write_guard next={0};
    for(size_t i=0;i<g->count;i++) {
        struct vm_write_region r=g->regions[i];
        int rc=0;
        if(r.end<=begin || r.begin>=end)rc=append(&next,r.begin,r.end);
        else {
            if(r.begin<begin)rc=append(&next,r.begin,begin);
            if(!rc && r.end>end)rc=append(&next,end,r.end);
        }
        if(rc)return rc;
    }
    *g=next;return 0;
}
bool vm_write_covers(const struct vm_write_guard *g, uintptr_t begin, uintptr_t end)
{
    if(!g || begin>=end || g->count>VM_WRITE_REGIONS)return false;
    for(size_t i=0;i<g->count;i++)
        if(g->regions[i].begin<=begin && g->regions[i].end>=end)return true;
    return false;
}
