/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "fd_registry.h"
int main(void)
{
    struct fd_registry r;
    struct fd_task_slot tasks[4];
    struct fd_table_slot tables[2];
    struct fd_record records[8];
    struct fd_task_handle root,copy,share,spare,found,unchanged={99,123};
    assert(fd_registry_init(&r,tasks,4,tables,2,records,4)==0);
    assert(fd_registry_create(&r,&root)==0);
    assert(fd_registry_find(&r,100,&found)==-ENOENT);
    assert(fd_registry_retire(&r,root)==-EBUSY);
    assert(fd_registry_clone(&r,root,FD_CLONE_COPY,&copy)==-ESTALE);
    struct fd_table *source=fd_registry_table(&r,root);assert(source);
    assert(fd_table_open(source,3,(struct fd_origin){7,FD_ACCESS_RO},1)==0);
    assert(fd_table_dup(source,3,4,0)==0);
    assert(fd_registry_publish(&r,root,100)==0);
    assert(fd_registry_publish(&r,root,100)==0);
    assert(fd_registry_publish(&r,root,101)==-EEXIST);
    assert(fd_registry_cancel(&r,root)==-EBUSY);
    assert(fd_registry_clone(&r,root,FD_CLONE_COPY,&copy)==0);
    struct fd_table *snapshot=fd_registry_table(&r,copy);assert(snapshot!=source);
    assert(fd_table_get(snapshot,3)->description==fd_table_get(snapshot,4)->description);
    fd_table_close(source,3);assert(fd_table_get(snapshot,3));
    assert(fd_registry_publish(&r,copy,100)==-EEXIST);
    assert(fd_registry_find(&r,101,&found)==-ENOENT);
    assert(fd_registry_publish(&r,copy,101)==0);
    assert(fd_registry_create(&r,&unchanged)==-ENOSPC); /* tables full */
    assert(unchanged.slot==99 && unchanged.generation==123);
    assert(fd_registry_clone(&r,root,FD_CLONE_SHARE,&share)==0);
    assert(fd_registry_table(&r,share)==source);
    assert(fd_registry_publish(&r,share,102)==0);
    assert(fd_registry_clone(&r,root,FD_CLONE_SHARE,&spare)==0);
    assert(fd_registry_clone(&r,root,FD_CLONE_SHARE,&unchanged)==-ENOSPC); /* tasks full */
    assert(fd_registry_cancel(&r,spare)==0);
    assert(fd_registry_cancel(&r,spare)==-ESTALE);
    assert(fd_registry_retire(&r,root)==0);
    assert(fd_registry_table(&r,root)==NULL);
    assert(fd_table_get(fd_registry_table(&r,share),4)); /* sibling keeps table */
    assert(fd_registry_create(&r,&unchanged)==-ENOSPC);
    assert(fd_registry_retire(&r,share)==0); /* last shared owner */
    assert(fd_registry_create(&r,&found)==0);
    assert(found.slot==root.slot && found.generation!=root.generation);
    assert(fd_registry_table(&r,found)==source && source->serial==0);
    assert(fd_table_get(source,4)==NULL); /* recycled storage has no provenance */
    assert(fd_registry_publish(&r,found,100)==0); /* TID reuse */
    assert(fd_registry_retire(&r,root)==-ESTALE);
    assert(fd_registry_publish(&r,root,100)==-ESTALE);
    struct fd_task_handle live;
    assert(fd_registry_find(&r,100,&live)==0 && live.generation==found.generation);
    assert(fd_registry_retire(&r,copy)==0);
    assert(fd_registry_table(&r,copy)==NULL);
    assert(fd_registry_retire(&r,found)==0);
    for(unsigned i=0;i<100;i++) {
        assert(fd_registry_create(&r,&found)==0);
        assert(fd_registry_cancel(&r,found)==0);
    }
    assert(tables[0].owners==0 && tables[1].owners==0);
    r.serial=UINT64_MAX;
    assert(fd_registry_create(&r,&unchanged)==-EOVERFLOW);
    assert(unchanged.slot==99 && unchanged.generation==123);
    assert(fd_registry_find(&r,0,&found)==-EINVAL);
    assert(fd_registry_init(&r,tasks,4,tables,2,records,SIZE_MAX)==-EINVAL);
    puts("PASS: FD registry capacity, copy/share ownership, cancellation, stale handles, TID reuse and generation overflow");
    return 0;
}
