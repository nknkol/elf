/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include "fd_experiment.h"
#include "fd_close_exec.h"
#include "clone_notify.h"
#include "syscall_hooks.h"
#define CAPACITY 128
static struct fd_registry registry;
static struct fd_task_slot tasks[1];
static struct fd_table_slot tables[1];
static struct fd_record records[CAPACITY];
static struct fd_close_queue queue;
static struct fd_close_slot pending[8];
static struct fd_guard guard;
static struct fd_task_handle owner;
static int initialized;
static long owner_tid;
extern long fd_receive_message(struct fd_table *,long [6]);
extern long raw_syscall(long,long,long,long,long,long,long);
int clone_observer_before(struct clone_event *event)
{ (void)event;return -ENOSYS; }
static int start(void)
{
    long tid=raw_syscall(__NR_gettid,0,0,0,0,0,0);
    if(tid<=0)return tid<0?(int)tid:-EIO;
    int state=__atomic_load_n(&initialized,__ATOMIC_ACQUIRE);
    if(state==2)return tid==owner_tid?0:-EOPNOTSUPP;
    int empty=0;
    if(!__atomic_compare_exchange_n(&initialized,&empty,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return -EAGAIN;
    fd_registry_init(&registry,tasks,1,tables,1,records,CAPACITY);
    fd_close_queue_init(&queue,pending,8);
    fd_registry_create(&registry,&owner);
    fd_registry_publish(&registry,owner,tid);
    owner_tid=tid;
    __atomic_store_n(&initialized,2,__ATOMIC_RELEASE);
    return 0;
}
static int room(struct fd_table *t,int target)
{
    if(t->serial==UINT64_MAX)return -EOVERFLOW;
    if(target>=0 && fd_table_get(t,target))return 0;
    for(size_t i=0;i<t->capacity;i++)if(t->slots[i].fd<0)return 0;
    return -ENOSPC;
}
long fd_experiment_dispatch(long n,long a[6])
{
    int rc=start();if(rc)return rc;
    struct fd_table *t=fd_registry_table(&registry,owner);
    if(n==__NR_prctl && a[0]==PR_ELF_FD_QUERY) {
        if(a[1]==0) { long count=0;for(size_t i=0;i<t->capacity;i++)count+=t->slots[i].fd>=0;return count; }
        const struct fd_record *r=fd_table_get(t,(int)a[2]);if(!r)return -ENOENT;
        if(a[1]==1)return r->generation;
        if(a[1]==2)return r->description;
        if(a[1]==3)return r->cloexec;
        return -EINVAL;
    }
    /* No partial support for lifecycle or alternate FD creation in this mode. */
    switch(n) {
    case __NR_clone: case __NR_clone3: case __NR_execve: case __NR_execveat:
    case __NR_close_range: case __NR_unshare: case __NR_openat2:
    case __NR_recvmmsg:
    case __NR_inotify_init1: case __NR_signalfd4:
    case __NR_pidfd_getfd: case __NR_io_uring_setup:
        return -ENOSYS;
    }
    if(n==__NR_close) { int bookkeeping;return fd_close_execute(&queue,&registry,&guard,owner,(int)a[0],&bookkeeping); }
    int duplicate=n==__NR_dup || n==__NR_dup3 ||
        (n==__NR_fcntl && (a[1]==F_DUPFD || a[1]==F_DUPFD_CLOEXEC));
    int setfd=n==__NR_fcntl && a[1]==F_SETFD;
    int create=n==__NR_openat || n==__NR_memfd_create || n==__NR_eventfd2 ||
        n==__NR_epoll_create1 || n==__NR_timerfd_create || n==__NR_socket ||
        n==__NR_accept || n==__NR_accept4;
    int pair=n==__NR_pipe2 || n==__NR_socketpair;
    int receive=n==__NR_recvmsg;
    if(!create && !pair && !duplicate && !setfd && !receive)return syscall_handle_common(n,a);
    /* The entry trampoline rejects same-TID nested slow calls in this build;
     * clone is denied, so no metadata writer can run across these syscalls.
     * Never generalize this to a multithreaded permission mode. */
    rc=fd_close_drain(&queue,&registry);if(rc<0)return rc;
    if(fd_close_pending(&queue,t,-1))return -EBUSY;
    if(receive)return fd_receive_message(t,a);
    rc=room(t,n==__NR_dup3?(int)a[1]:setfd?(int)a[0]:-1);if(rc)return rc;
    if(pair) {
        if(t->serial>UINT64_MAX-2)return -EOVERFLOW;
        size_t free_slots=0;
        for(size_t i=0;i<t->capacity;i++)free_slots+=t->slots[i].fd<0;
        if(free_slots<2)return -ENOSPC;
    }
    long result=syscall_handle_common(n,a);
    if(result<0)return result;
    if(pair) {
        /* Read only after kernel success. This relies on the experimental
         * single-task AArch64 address space and nested slow-call exclusion;
         * it is not a general user-memory snapshot for concurrent guests. */
        const int *fds=(const int *)a[n==__NR_pipe2?0:3];
        int first=fds[0],second=fds[1];
        rc=fd_table_open(t,first,(struct fd_origin){0,FD_ACCESS_UNKNOWN},!!(a[1]&O_CLOEXEC));
        if(!rc)rc=fd_table_open(t,second,(struct fd_origin){0,FD_ACCESS_UNKNOWN},!!(a[1]&O_CLOEXEC));
    }
    else if(create) {
        /* MFD_CLOEXEC is bit 0, unlike O_CLOEXEC/EFD_CLOEXEC. */
        int cloexec=n==__NR_accept?0:n==__NR_accept4?!!(a[3]&O_CLOEXEC):
            n==__NR_memfd_create?!!(a[1]&1):
            n==__NR_epoll_create1?!!(a[0]&O_CLOEXEC):
            (n==__NR_eventfd2 || n==__NR_timerfd_create || n==__NR_socket)?!!(a[1]&O_CLOEXEC):!!(a[2]&O_CLOEXEC);
        rc=fd_table_open(t,(int)result,(struct fd_origin){0,FD_ACCESS_UNKNOWN},cloexec);
    }
    else if(setfd)rc=fd_table_set_cloexec(t,(int)a[0],!!(a[2]&FD_CLOEXEC));
    else rc=fd_table_dup(t,(int)a[0],(int)result,n==__NR_dup3?!!(a[2]&O_CLOEXEC):n==__NR_fcntl && a[1]==F_DUPFD_CLOEXEC);
    /* Preflight plus single-task exclusion guarantees capacity/serial here. */
    if(rc)return rc;
    return result;
}
