/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "fd_close_queue.h"
#include "fd_guard.h"
static struct fd_registry registry;
static struct fd_close_queue queue;
static struct fd_guard guard;
static struct fd_task_handle owner;
static struct fd_close_ticket operation;
static pthread_barrier_t held,published;
static int fd;
static void barrier(pthread_barrier_t *b)
{ int rc=pthread_barrier_wait(b);assert(rc==0 || rc==PTHREAD_BARRIER_SERIAL_THREAD); }
static void *drainer(void *unused)
{
    (void)unused;
    struct fd_guard_lease lease;
    assert(fd_guard_enter(&guard,syscall(SYS_gettid),&lease)==0);
    /* Fault-injection coordination only: production guard sections never wait. */
    barrier(&held);barrier(&published);
    assert(fd_registry_retire(&registry,owner)==-EBUSY);
    assert(fd_close_pending(&queue,fd_registry_table(&registry,owner),fd));
    assert(fd_close_drain(&queue,&registry)==1);
    assert(fd_close_drain(&queue,&registry)==0);
    assert(fd_table_get(fd_registry_table(&registry,owner),fd)==NULL);
    assert(fd_guard_leave(&guard,lease)==0);
    return NULL;
}
int main(void)
{
    struct fd_task_slot tasks[3];struct fd_table_slot tables[2];struct fd_record records[8];
    struct fd_close_slot slots[2];
    assert(fd_registry_init(&registry,tasks,3,tables,2,records,4)==0);
    assert(fd_close_queue_init(&queue,slots,2)==0);
    assert(fd_registry_create(&registry,&owner)==0);
    assert(fd_registry_publish(&registry,owner,syscall(SYS_gettid))==0);
    struct fd_table *table=fd_registry_table(&registry,owner);
    fd=open("/dev/null",O_RDONLY);assert(fd>=0);
    assert(fd_table_open(table,fd,(struct fd_origin){7,FD_ACCESS_RO},0)==0);
    assert(fd_close_prepare(&queue,&registry,owner,fd,&operation)==0);
    assert(fd_close_drain(&queue,&registry)==0); /* unknown outcome stays pinned */
    assert(fd_registry_retire(&registry,owner)==-EBUSY);
    assert(pthread_barrier_init(&held,NULL,2)==0 && pthread_barrier_init(&published,NULL,2)==0);
    pthread_t thread;assert(pthread_create(&thread,NULL,drainer,NULL)==0);
    barrier(&held);
    struct fd_guard_lease lease={0};
    assert(fd_guard_enter(&guard,syscall(SYS_gettid),&lease)==-EAGAIN);
    assert(close(fd)==0); /* execute once, despite unavailable metadata guard */
    assert(fd_close_publish(&queue,operation,FD_CLOSE_REMOVE)==0);
    assert(fd_close_publish(&queue,operation,FD_CLOSE_KEEP)==-ESTALE);
    barrier(&published);assert(pthread_join(thread,NULL)==0);
    assert(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
    struct fd_task_handle sibling;
    assert(fd_registry_clone(&registry,owner,FD_CLONE_SHARE,&sibling)==0);
    assert(fd_registry_publish(&registry,sibling,syscall(SYS_gettid)+1)==0);
    struct fd_close_ticket newer,second,untouched={99,123};
    assert(fd_close_prepare(&queue,&registry,owner,fd,&newer)==0);
    assert(newer.token!=operation.token && newer.slot==operation.slot);
    assert(fd_close_publish(&queue,operation,FD_CLOSE_REMOVE)==-ESTALE);
    assert(fd_close_pending(&queue,table,-1));
    assert(fd_close_prepare(&queue,&registry,sibling,fd,&untouched)==-EBUSY);
    assert(fd_close_prepare(&queue,&registry,owner,fd+100,&second)==0);
    assert(fd_close_prepare(&queue,&registry,owner,fd+101,&untouched)==-ENOSPC);
    assert(untouched.slot==99 && untouched.token==123);
    assert(tasks[owner.slot].pending==2);
    /* These two reservations never entered the kernel: explicit cancellation. */
    assert(fd_close_publish(&queue,newer,FD_CLOSE_KEEP)==0);
    assert(fd_close_publish(&queue,second,FD_CLOSE_KEEP)==0);
    assert(fd_close_drain(&queue,&registry)==2);
    assert(tasks[owner.slot].pending==0 && !fd_close_pending(&queue,table,-1));
    /* Late completion cannot erase a new record, even when an external actor
     * bypasses the pending check. This does not solve pre-kernel reuse. */
    assert(fd_table_open(table,fd,(struct fd_origin){8,FD_ACCESS_RO},0)==0);
    assert(fd_close_prepare(&queue,&registry,owner,fd,&newer)==0);
    assert(fd_table_open(table,fd,(struct fd_origin){9,FD_ACCESS_RW},1)==0);
    assert(fd_close_publish(&queue,newer,FD_CLOSE_REMOVE)==0);
    assert(fd_close_drain(&queue,&registry)==1);
    assert(fd_table_get(table,fd)->origin.mount_id==9);
    assert(fd_close_prepare(&queue,&registry,owner,fd,&newer)==0);
    assert(fd_close_publish(&queue,newer,FD_CLOSE_KEEP)==0);
    assert(fd_close_drain(&queue,&registry)==1);
    assert(fd_table_get(table,fd)->origin.mount_id==9);
    /* No fresh token can wrap and become equal to a stale operation. */
    slots[0].state=UINT64_MAX & ~UINT64_C(3);
    slots[1].state=UINT64_MAX & ~UINT64_C(3);
    assert(fd_close_prepare(&queue,&registry,owner,fd,&untouched)==-EOVERFLOW);
    assert(tasks[owner.slot].pending==0);
    assert(fd_registry_retire(&registry,owner)==0);
    assert(fd_registry_unpin(&registry,owner)==-ESTALE);
    assert(fd_registry_table(&registry,sibling)==table);
    assert(fd_registry_retire(&registry,sibling)==0);
    assert(pthread_barrier_destroy(&held)==0 && pthread_barrier_destroy(&published)==0);
    puts("PASS: reserved close queue publishes under contention, drains once, pins table lifetime and rejects overlap/stale tokens");
    return 0;
}
