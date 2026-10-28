/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <asm/ioctls.h>
#include <linux/sched.h>
#include "reentry_guard.h"
#include "fd_experiment.h"
#include "fs_policy.h"
#include "fd_handoff.h"
#include "config.h"
#include "fd_close_exec.h"
#include "clone_notify.h"
#include "syscall_hooks.h"
#include "proot_bridge.h"
#include <string.h>
#define CAPACITY 128
struct fd_runtime {
    struct fd_registry registry;
    struct fd_task_slot tasks[1];
    struct fd_table_slot tables[1];
    struct fd_record records[CAPACITY];
    struct fd_close_queue queue;
    struct fd_close_slot pending[8];
    struct fd_guard guard;
    struct fd_task_handle owner;
    int initialized, init_error;
    long owner_tid;
    struct proot_open_origin cwd;
};
static struct fd_runtime primary, vfork_child;
static int vfork_active;
static struct scratch_slot { void *address;size_t size;int used; } scratch[2];
#define STATE_BYTES (FD_SNAPSHOT_HEADER_BYTES+CAPACITY*FD_SNAPSHOT_ENTRY_BYTES)
extern long fd_receive_messages(struct fd_table *,long [6]);
extern long fd_receive_message(struct fd_table *,long [6]);
extern long raw_syscall(long,long,long,long,long,long,long);
static int start(struct fd_runtime *s);
static struct fd_runtime *current(void)
{
    if(!vfork_active)return &primary;
    long tid=raw_syscall(__NR_gettid,0,0,0,0,0,0);
    return vfork_active && tid==vfork_child.owner_tid ? &vfork_child : &primary;
}
static void scratch_discard(void)
{
    for(int i=0;i<2;i++) {
        if(scratch[i].address)
            raw_syscall(__NR_munmap,(long)scratch[i].address,scratch[i].size,0,0,0,0);
        scratch[i]=(struct scratch_slot){0};
    }
}
static int scratch_prepare(void)
{
    size_t sizes[]={proot_bridge_scratch_size(),proot_exec_scratch_size()};
    for(int i=0;i<2;i++) {
        long mem=raw_syscall(__NR_mmap,0,sizes[i],3,0x22,-1,0);
        if((unsigned long)mem>=(unsigned long)-4095) { scratch_discard();return mem; }
        scratch[i]=(struct scratch_slot){(void *)mem,sizes[i],0};
    }
    return 0;
}
int clone_observer_before(struct clone_event *event)
{
    unsigned long allowed=CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID;
    int vf=event->flags==(CLONE_VM|CLONE_VFORK|17ul);
    if(!vf && ((event->flags & 255)!=17 || (event->flags & ~(allowed|255ul))))return -ENOSYS;
    /* One suspended parent and one child only. No nested clone or threads. */
    if(vfork_active)return -ENOSYS;
    struct reentry_slot *slot=reentry_try_enter();
    if(!slot)return -EDEADLK;
    if((uintptr_t)slot>=(uintptr_t)-4095)return (long)slot;
    struct fd_runtime *s=&primary;
    int rc=start(s);
    if(!rc)rc=fd_close_drain(&s->queue,&s->registry);
    if(rc>=0 && fd_close_pending(&s->queue,fd_registry_table(&s->registry,s->owner),-1))rc=-EBUSY;
    if(rc<0) { reentry_leave(slot);return rc; }
    if(vf) {
        rc=scratch_prepare();
        if(rc) { reentry_leave(slot);return rc; }
        vfork_child=*s;
        /* Fix all pointers into the copied arena; no pending close pins exist. */
        vfork_child.registry.tasks=vfork_child.tasks;
        vfork_child.registry.tables=vfork_child.tables;
        vfork_child.tables[0].table.slots=vfork_child.records;
        fd_close_queue_init(&vfork_child.queue,vfork_child.pending,8);
        vfork_child.owner_tid=0;
        vfork_active=1;
    }
    /* Only the returning parent dereferences this lease. A private-fork
     * descendant may hold a private slot; child finish/cleanup never touch it. */
    event->cookie=slot;
    return 0;
}
void clone_observer_finish(const struct clone_event *event,long result)
{
    int vf=event->flags==(CLONE_VM|CLONE_VFORK|17ul);
    if(result) {
        if(vf) {
            /* Kernel vfork return proves the child left this VM (exec/exit),
             * or clone failed. Its FD changes never touched primary. */
            scratch_discard();
            reentry_vfork_end();
            vfork_active=0;
        }
        reentry_leave(event->cookie);return;
    }
    struct fd_runtime *s=vf?&vfork_child:&primary;
    long tid=raw_syscall(__NR_gettid,0,0,0,0,0,0);
    if(vf)reentry_vfork_begin(tid);
    else reentry_private_fork(tid);
    s->tasks[s->owner.slot].clone.child_tid=0;
    int rc=fd_registry_publish(&s->registry,s->owner,tid);
    if(rc) {
        s->init_error=rc;
        __atomic_store_n(&s->initialized,3,__ATOMIC_RELEASE);
        return;
    }
    s->owner_tid=tid;
}
/* Parent-owned reservations remove the child mmap/publication and
 * munmap/unregistration death windows for the migrated path/exec scratch. */
long fd_experiment_scratch_alloc(size_t size)
{
    if(current()!=&vfork_child)return raw_syscall(__NR_mmap,0,size,3,0x22,-1,0);
    int best=-1;
    for(int i=0;i<2;i++)if(!scratch[i].used && size<=scratch[i].size &&
        (best<0 || scratch[i].size<scratch[best].size))best=i;
    if(best>=0) {
        scratch[best].used=1;
        memset(scratch[best].address,0,size);
        return (long)scratch[best].address;
    }
    return -ENOMEM;
}
void fd_experiment_scratch_free(void *address,size_t size)
{
    if(current()==&vfork_child) {
        for(int i=0;i<2;i++)if(scratch[i].address==address) {
            scratch[i].used=0;return;
        }
        return;
    }
    raw_syscall(__NR_munmap,(long)address,size,0,0,0,0);
}
static int start(struct fd_runtime *s)
{
    long tid=raw_syscall(__NR_gettid,0,0,0,0,0,0);
    if(tid<=0)return tid<0?(int)tid:-EIO;
    int state=__atomic_load_n(&s->initialized,__ATOMIC_ACQUIRE);
    if(state==2)return tid==s->owner_tid?0:-EOPNOTSUPP;
    if(state==3)return s->init_error;
    int empty=0;
    if(!__atomic_compare_exchange_n(&s->initialized,&empty,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return -EAGAIN;
    fd_registry_init(&s->registry,s->tasks,1,s->tables,1,s->records,CAPACITY);
    fd_close_queue_init(&s->queue,s->pending,8);
    fd_registry_create(&s->registry,&s->owner);
    fd_registry_publish(&s->registry,s->owner,tid);
    if(g_payload_config.fd_state>=0) {
        unsigned char snapshot[STATE_BYTES];
        struct fd_table *table=fd_registry_table(&s->registry,s->owner);
        int transport=g_payload_config.fd_state;
        int rc=fd_handoff_restore(table,transport,snapshot,sizeof(snapshot));
        if(!rc)for(size_t i=0;i<table->capacity;i++) {
            struct fd_record *record=&table->slots[i];
            if(record->fd<0)continue;
            long flags=raw_syscall(__NR_fcntl,record->fd,F_GETFD,0,0,0,0);
            if(record->fd==transport || flags<0 || (flags&FD_CLOEXEC)) { rc=-ESTALE;break; }
            /* Serialized metadata is not permission authority. */
            record->origin=(struct fd_origin){0,FD_ACCESS_UNKNOWN};
        }
        raw_syscall(__NR_close,transport,0,0,0,0,0);
        g_payload_config.fd_state=-1;
        if(rc) {
            s->init_error=rc;
            __atomic_store_n(&s->initialized,3,__ATOMIC_RELEASE);
            return rc;
        }
    }
    s->owner_tid=tid;
    __atomic_store_n(&s->initialized,2,__ATOMIC_RELEASE);
    return 0;
}
long fd_experiment_export(void)
{
    struct fd_runtime *s=current();
    unsigned char snapshot[STATE_BYTES];
    return fd_handoff_create(fd_registry_table(&s->registry,s->owner),snapshot,sizeof(snapshot));
}
static int room(struct fd_table *t,int target,int assign)
{
    int existing=target>=0 && fd_table_get(t,target);
    if(t->serial==UINT64_MAX && (assign || !existing))return -EOVERFLOW;
    if(existing)return 0;
    for(size_t i=0;i<t->capacity;i++)if(t->slots[i].fd<0)return 0;
    return -ENOSPC;
}
long fd_experiment_dispatch(long n,long a[6])
{
    struct fd_runtime *s=current();
    int rc=start(s);if(rc)return rc;
    struct fd_table *t=fd_registry_table(&s->registry,s->owner);
    if(n==__NR_prctl && a[0]==PR_ELF_FD_QUERY) {
        /* Diagnostic only: decision for a supplied mount ID, not an FD grant. */
        if(a[1]==6) {
            const char *v=g_payload_config.mount_access_observe;
            if(!v[0])return -ENODATA;
            enum fs_access access[CONFIG_MAX_BINDS+1];
            size_t count=0;
            for(;count<CONFIG_MAX_BINDS+1 && v[count];count++) {
                if(v[count]!='d' && v[count]!='r' && v[count]!='w')return -EINVAL;
                access[count]=v[count]=='d'?FS_DENY:v[count]=='r'?FS_READ_ONLY:FS_READ_WRITE;
            }
            if(v[count])return -EINVAL;
            struct fs_policy policy={access,count};
            int valid=fs_policy_validate(&policy,g_payload_config.bind_count);
            if(valid)return valid;
            return fs_policy_check(&policy,(size_t)a[2],true,(enum fs_operation)a[3]);
        }
        if(a[1]==0) { long count=0;for(size_t i=0;i<t->capacity;i++)count+=t->slots[i].fd>=0;return count; }
        const struct fd_record *r=fd_table_get(t,(int)a[2]);if(!r)return -ENOENT;
        if(a[1]==1)return r->generation;
        if(a[1]==2)return r->description;
        if(a[1]==3)return r->cloexec;
        if(a[1]==4)return r->origin.mount_id;
        if(a[1]==5)return r->origin.access;
        return -EINVAL;
    }
    if(n==__NR_chdir || n==__NR_fchdir || n==__NR_getcwd) {
        struct proot_open_origin anchor=s->cwd,next={0,false};
        if(n==__NR_fchdir) {
            anchor=(struct proot_open_origin){0,false};
            const struct fd_record *r=fd_table_get(t,(int)a[0]);
            if(r && r->origin.access!=FD_ACCESS_UNKNOWN)
                anchor=(struct proot_open_origin){r->origin.mount_id,true};
        }
        long result=proot_cwd(n,a,&anchor,&next);
        if(result>=0 && n!=__NR_getcwd)s->cwd=next;
        return result;
    }
    /* No partial support for lifecycle or alternate FD creation in this mode. */
    switch(n) {
    case __NR_clone: case __NR_clone3:
    case __NR_close_range: case __NR_unshare:
#define FD_UNSUPPORTED(n) case n:
#include "fd_unsupported_syscalls.inc"
#undef FD_UNSUPPORTED
        return -ENOSYS;
    }
    /* TIOCGPTPEER returns a new FD; do not treat it as an ordinary ioctl.
     * Native success is not available in this sandbox, so keep it unsupported. */
    if(n==__NR_ioctl && (unsigned)a[1]==TIOCGPTPEER)return -ENOSYS;
    if(n==__NR_close) { int bookkeeping;return fd_close_execute(&s->queue,&s->registry,&s->guard,s->owner,(int)a[0],&bookkeeping); }
    unsigned long openat2_flags=0,openat2_resolve=0;
    if(n==__NR_openat2) {
        /* Snapshot before use. Only the published 24-byte ABI and this narrow
         * flag combination are supported; never silently discard resolve. */
        if(a[3]!=24)return -ENOSYS;
        if(!a[2])return -EFAULT;
        uint64_t how[3];memcpy(how,(void *)a[2],sizeof(how));
        if((how[2]!=0 && how[2]!=8) || how[1] ||
           (how[0] & ~(uint64_t)(O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)) ||
           (how[0] & (O_PATH|O_NOFOLLOW))!=(O_PATH|O_NOFOLLOW))return -EOPNOTSUPP;
        openat2_flags=how[0];openat2_resolve=how[2];
    }
    int duplicate=n==__NR_dup || n==__NR_dup3 ||
        (n==__NR_fcntl && (a[1]==F_DUPFD || a[1]==F_DUPFD_CLOEXEC));
    int ioctl_setfd=n==__NR_ioctl && ((unsigned)a[1]==FIOCLEX || (unsigned)a[1]==FIONCLEX);
    int setfd=(n==__NR_fcntl && a[1]==F_SETFD) || ioctl_setfd;
    int create=n==__NR_openat2 || n==__NR_openat || n==__NR_memfd_create || n==__NR_eventfd2 ||
        n==__NR_epoll_create1 || n==__NR_timerfd_create || n==__NR_socket ||
        n==__NR_accept || n==__NR_accept4 || n==__NR_inotify_init1 ||
        n==__NR_pidfd_open || n==__NR_pidfd_getfd ||
        (n==__NR_signalfd4 && (int)a[0]==-1);
    /* signalfd4 with an existing FD updates its mask, not its identity/flags.
     * Let the kernel validate it without requiring a new metadata slot. */
    int pair=n==__NR_pipe2 || n==__NR_socketpair;
    int execute=n==__NR_execve || n==__NR_execveat;
    int receive=n==__NR_recvmsg || n==__NR_recvmmsg;
    if(!create && !pair && !duplicate && !setfd && !receive && !execute) {
        if(proot_handles_syscall(n)) {
            struct proot_path_context context={.cwd=s->cwd,
                .fd={(int)a[n==__NR_symlinkat?1:0],AT_FDCWD}};
            if(n==__NR_linkat || n==__NR_renameat || n==__NR_renameat2)
                context.fd[1]=(int)a[2];
            for(size_t i=0;i<2;i++) {
                if(context.fd[i]==AT_FDCWD)continue;
                const struct fd_record *r=fd_table_get(t,context.fd[i]);
                if(r && r->origin.access!=FD_ACCESS_UNKNOWN)
                    context.directory[i]=(struct proot_open_origin){r->origin.mount_id,true};
            }
            return proot_context_syscall(n,a,&context);
        }
        return syscall_handle_common(n,a);
    }
    /* The entry trampoline rejects same-TID nested slow calls in this build;
     * each supported task has its own metadata arena across these syscalls.
     * Never generalize this to a multithreaded permission mode. */
    rc=fd_close_drain(&s->queue,&s->registry);if(rc<0)return rc;
    if(fd_close_pending(&s->queue,t,-1))return -EBUSY;
    if(execute) {
        struct proot_path_context context={.cwd=s->cwd,.fd={AT_FDCWD,AT_FDCWD}};
        if(n==__NR_execveat && (int)a[0]!=AT_FDCWD) {
            context.fd[0]=(int)a[0];
            const struct fd_record *r=fd_table_get(t,context.fd[0]);
            if(r && r->origin.access!=FD_ACCESS_UNKNOWN)
                context.directory[0]=(struct proot_open_origin){r->origin.mount_id,true};
        }
        return proot_execve_context(n,a,&context);
    }
    if(receive)return n==__NR_recvmsg?fd_receive_message(t,a):fd_receive_messages(t,a);
    rc=room(t,n==__NR_dup3?(int)a[1]:setfd?(int)a[0]:-1,!setfd);if(rc)return rc;
    if(pair) {
        if(t->serial>UINT64_MAX-2)return -EOVERFLOW;
        size_t free_slots=0;
        for(size_t i=0;i<t->capacity;i++)free_slots+=t->slots[i].fd<0;
        if(free_slots<2)return -ENOSPC;
    }
    struct proot_open_origin opened={0,false},anchor=s->cwd;
    if((n==__NR_openat || n==__NR_openat2) && (int)a[0]!=AT_FDCWD) {
        anchor=(struct proot_open_origin){0,false};
        const struct fd_record *directory=fd_table_get(t,(int)a[0]);
        if(directory && directory->origin.access!=FD_ACCESS_UNKNOWN)
            anchor=(struct proot_open_origin){directory->origin.mount_id,true};
    }
    long result;
    if(n==__NR_openat2) {
        if(openat2_resolve==8)
            result=proot_open_beneath((int)a[0],(const char *)a[1],openat2_flags,&anchor,&opened);
        else {
            /* resolve=0 adds no traversal constraints. Validated O_PATH flags
             * can use the existing guest path backend, including absolute
             * paths and bindings; never send the guest spelling to the host. */
            long open_args[6]={a[0],a[1],openat2_flags,0,0,0};
            result=proot_openat(open_args,&anchor,&opened);
        }
    } else if(n==__NR_openat)result=proot_openat(a,&anchor,&opened);
    else result=syscall_handle_common(n,a);
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
        int cloexec=n==__NR_openat2?!!(openat2_flags&O_CLOEXEC):(n==__NR_pidfd_open || n==__NR_pidfd_getfd)?1:n==__NR_accept?0:(n==__NR_accept4 || n==__NR_signalfd4)?!!(a[3]&O_CLOEXEC):
            n==__NR_memfd_create?!!(a[1]&1):
            (n==__NR_epoll_create1 || n==__NR_inotify_init1)?!!(a[0]&O_CLOEXEC):
            (n==__NR_eventfd2 || n==__NR_timerfd_create || n==__NR_socket)?!!(a[1]&O_CLOEXEC):!!(a[2]&O_CLOEXEC);
        rc=n==__NR_pidfd_getfd?fd_table_import_unknown(t,(int)result,cloexec):
            /* Existing root/bind configuration is writable. This is a source
             * tag, not O_ACCMODE or permission enforcement; unknown anchors,
             * imported FDs and exec restore deliberately remain UNKNOWN. */
            fd_table_open(t,(int)result,(struct fd_origin){opened.mount_id,
                          opened.known?FD_ACCESS_RW:FD_ACCESS_UNKNOWN},cloexec);
    }
    else if(setfd)rc=fd_table_set_cloexec(t,(int)a[0],ioctl_setfd?(unsigned)a[1]==FIOCLEX:!!(a[2]&FD_CLOEXEC));
    else rc=fd_table_dup(t,(int)a[0],(int)result,n==__NR_dup3?!!(a[2]&O_CLOEXEC):n==__NR_fcntl && a[1]==F_DUPFD_CLOEXEC);
    /* Preflight plus single-task exclusion guarantees capacity/serial here. */
    if(rc)return rc;
    return result;
}
