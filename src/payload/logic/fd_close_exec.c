/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include "fd_close_exec.h"
extern long raw_syscall(long,long,long,long,long,long,long);
long fd_close_execute(struct fd_close_queue *q,struct fd_registry *r,struct fd_guard *g,
                      struct fd_task_handle owner,int fd,int *bookkeeping)
{
    if (!bookkeeping) return -EINVAL;
    *bookkeeping=0;
    if (!q || !r || !g) return *bookkeeping=-EINVAL;
    if (fd<0) return -EBADF;
    long tid=raw_syscall(__NR_gettid,0,0,0,0,0,0);
    if (tid<=0) return *bookkeeping=tid<0?(int)tid:-EIO;
    struct fd_guard_lease lease;
    int rc=fd_guard_enter(g,tid,&lease);
    if (rc) return *bookkeeping=rc;
    struct fd_close_ticket ticket;
    struct fd_task_handle current;
    rc=fd_registry_find(r,tid,&current);
    if (!rc && (current.slot!=owner.slot || current.generation!=owner.generation)) rc=-ESTALE;
    if (!rc) rc=fd_close_drain(q,r);
    if (rc>=0) rc=fd_close_prepare(q,r,owner,fd,&ticket);
    int left=fd_guard_leave(g,lease);
    if (rc || left) return *bookkeeping=rc?rc:left;
    long result=raw_syscall(__NR_close,fd,0,0,0,0,0);
    /* EBADF proves this descriptor absent at kernel close, not an unchanged
     * stale metadata entry. Generation checks still protect later adoption. */
    if (result && result!=-EBADF) {
        *bookkeeping=-EINPROGRESS;
        return result;
    }
    rc=fd_close_publish(q,ticket,FD_CLOSE_REMOVE);
    if (rc) { *bookkeeping=rc;return result; }
    rc=fd_guard_enter(g,tid,&lease);
    if (rc) { *bookkeeping=rc;return result; }
    rc=fd_close_drain(q,r);
    left=fd_guard_leave(g,lease);
    *bookkeeping=rc<0?rc:left;
    return result;
}
