/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "fd_snapshot.h"
int main(void)
{
    struct fd_record slots[8], child_slots[8], imported_slots[8];
    struct fd_table t,child,imported;
    assert(fd_table_init(&t,slots,8)==0);
    assert(fd_table_init(&child,child_slots,8)==0);
    assert(fd_table_init(&imported,imported_slots,8)==0);
    assert(fd_table_open_pipe_writer(&t,10,0)==0);
    assert(fd_table_get(&t,10)->origin.access==FD_ACCESS_UNKNOWN);
    assert(fd_table_dup(&t,10,11,0)==0);
    assert(fd_table_get(&t,11)->pipe_writer);
    assert(fd_table_set_cloexec(&t,11,1)==0);
    assert(fd_table_get(&t,11)->pipe_writer);
    assert(fd_table_copy(&child,&t)==0);
    assert(fd_table_get(&child,10)->pipe_writer);
    fd_table_exec(&child);
    assert(!fd_table_get(&child,11) && !fd_table_get(&child,10)->pipe_writer);
    unsigned char bytes[FD_SNAPSHOT_HEADER_BYTES+8*FD_SNAPSHOT_ENTRY_BYTES];size_t size;
    assert(fd_snapshot_export(&t,bytes,sizeof(bytes),&size)==0);
    assert(fd_snapshot_import(&imported,bytes,size)==0);
    assert(!fd_table_get(&imported,10)->pipe_writer);
    assert(!fd_table_get(&imported,11));
    fd_table_close(&t,10);
    assert(fd_table_open(&t,10,(struct fd_origin){1,FD_ACCESS_RO},0)==0);
    assert(!fd_table_get(&t,10)->pipe_writer);
    assert(fd_table_dup(&t,10,11,0)==0 && !fd_table_get(&t,11)->pipe_writer);
    assert(fd_table_open_pipe_writer(&t,12,0)==0);
    assert(fd_table_import_unknown(&t,12,0)==0 && !fd_table_get(&t,12)->pipe_writer);
    assert(fd_table_open_pipe_writer(&t,12,2)==-EINVAL);
    puts("PASS: pipe grants follow dup/fork, not exec snapshots or slot reuse");
    return 0;
}
