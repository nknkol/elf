/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "fd_close_exec.h"
static struct fd_guard guard;
static struct fd_guard_lease blocker;
static int calls,inject_error,block_after,gettid_error;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f)
{
    if(n==SYS_gettid && gettid_error)return -gettid_error;
    if(n==SYS_close) {
        calls++;
        if(inject_error)return -inject_error; /* injected uncertainty, no native claim */
    }
    long result=syscall(n,a,b,c,d,e,f);if(result==-1)result=-errno;
    if(n==SYS_close && block_after) {
        assert(fd_guard_enter(&guard,syscall(SYS_gettid)+1,&blocker)==0);
    }
    return result;
}
int main(void)
{
    struct fd_registry r;struct fd_task_slot tasks[2];struct fd_table_slot tables[2];
    struct fd_record records[8];struct fd_close_queue q;struct fd_close_slot slots[3];
    struct fd_task_handle owner;
    assert(fd_registry_init(&r,tasks,2,tables,2,records,4)==0);
    assert(fd_close_queue_init(&q,slots,3)==0);
    assert(fd_registry_create(&r,&owner)==0);
    assert(fd_registry_publish(&r,owner,syscall(SYS_gettid))==0);
    struct fd_table *t=fd_registry_table(&r,owner);
    int fd=open("/dev/null",O_RDONLY);assert(fd>=0);
    assert(fd_table_open(t,fd,(struct fd_origin){17,FD_ACCESS_RO},0)==0);
    int bookkeeping;
    assert(fd_close_execute(&q,&r,&guard,owner,-1,&bookkeeping)==-EBADF && calls==0);
    struct fd_task_handle stale=owner;stale.generation++;
    assert(fd_close_execute(&q,&r,&guard,stale,fd,&bookkeeping)==-ESTALE && calls==0);
    gettid_error=EACCES;
    assert(fd_close_execute(&q,&r,&guard,owner,fd,&bookkeeping)==-EACCES && calls==0);
    gettid_error=0;
    assert(fd_guard_enter(&guard,syscall(SYS_gettid),&blocker)==0);
    assert(fd_close_execute(&q,&r,&guard,owner,fd,&bookkeeping)==-EDEADLK && calls==0);
    assert(fd_guard_leave(&guard,blocker)==0);
    block_after=1;
    assert(fd_close_execute(&q,&r,&guard,owner,fd,&bookkeeping)==0);
    assert(calls==1 && bookkeeping==-EAGAIN && fd_close_pending(&q,t,fd));
    assert(fd_table_get(t,fd) && fd_registry_retire(&r,owner)==-EBUSY);
    assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF); /* kernel already closed */
    block_after=0;
    assert(fd_guard_leave(&guard,blocker)==0);
    /* Next entry drains prior completion without repeating its close. Raw
     * EBADF then reconciles this new explicit close request independently. */
    assert(fd_close_execute(&q,&r,&guard,owner,fd,&bookkeeping)==-EBADF);
    assert(calls==2 && bookkeeping==0 && !fd_table_get(t,fd));
    assert(!fd_close_pending(&q,t,-1) && tasks[owner.slot].pending==0);
    assert(fd_table_open(t,fd,(struct fd_origin){18,FD_ACCESS_RO},0)==0);
    assert(fd_close_execute(&q,&r,&guard,owner,fd,&bookkeeping)==-EBADF);
    assert(calls==3 && !fd_table_get(t,fd)); /* stale native EBADF metadata */
    fd=open("/dev/null",O_RDONLY);assert(fd>=0);
    assert(fd_table_open(t,fd,(struct fd_origin){19,FD_ACCESS_RO},0)==0);
    assert(fd_close_execute(&q,&r,&guard,owner,fd,&bookkeeping)==0);
    assert(calls==4 && bookkeeping==0 && !fd_table_get(t,fd));
    /* Closing an untracked inherited FD must work even with a full metadata
     * table; removal requires a queue slot, not a new provenance entry. */
    for(int i=0;i<4;i++)assert(fd_table_open(t,1000+i,(struct fd_origin){20,FD_ACCESS_RO},0)==0);
    fd=open("/dev/null",O_RDONLY);assert(fd>=0 && !fd_table_get(t,fd));
    assert(fd_close_execute(&q,&r,&guard,owner,fd,&bookkeeping)==0);
    assert(calls==5 && bookkeeping==0 && fcntl(fd,F_GETFD)==-1 && errno==EBADF);
    for(int i=0;i<4;i++)assert(fd_table_get(t,1000+i)->origin.mount_id==20);
    /* Unknown errors are NOT guessed as KEEP/REMOVE and are never retried. */
    const int errors[]={EINTR,EACCES,EIO};
    for(unsigned i=0;i<3;i++) {
        inject_error=errors[i];
        assert(fd_close_execute(&q,&r,&guard,owner,100+(int)i,&bookkeeping)==-errors[i]);
        assert(bookkeeping==-EINPROGRESS);
    }
    assert(calls==8 && tasks[owner.slot].pending==3);
    assert(fd_close_execute(&q,&r,&guard,owner,100,&bookkeeping)==-EBUSY && calls==8);
    assert(fd_close_execute(&q,&r,&guard,owner,200,&bookkeeping)==-ENOSPC && calls==8);
    assert(fd_registry_retire(&r,owner)==-EBUSY && fd_close_drain(&q,&r)==0);
    struct fd_task_handle untouched={99,123};
    assert(fd_registry_clone(&r,owner,FD_CLONE_COPY,&untouched)==-EBUSY);
    assert(fd_registry_clone(&r,owner,FD_CLONE_SHARE,&untouched)==-EBUSY);
    assert(untouched.slot==99 && untouched.generation==123);
    puts("PASS: close execution preserves native results, defers bookkeeping without syscall retry, and quarantines injected uncertain errors");
    return 0;
}
