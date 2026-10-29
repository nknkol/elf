/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <asm/ioctls.h>
#include <asm/termbits.h>
#include <asm/stat.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <sys/mman.h>
#include <elf.h>
#include "vm_write_guard.h"
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
    struct vm_write_guard mappings;
    uint64_t stdio_output[2]; /* Local description IDs, never serialized as grants. */
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
static int admit_stdio_output(struct fd_runtime *s)
{
    if(!g_payload_config.allow_stdio_output)return 0;
    if(g_payload_config.guard_path_mutations!=2)return -EINVAL;
    struct fd_table *table=fd_registry_table(&s->registry,s->owner);
    for(int fd=1;fd<=2;fd++) {
        struct stat st;
        _Static_assert(sizeof(st)==128 && offsetof(struct stat,st_mode)==16,
                       "AArch64 kernel stat layout required");
        if(raw_syscall(__NR_fstat,fd,(long)&st,0,0,0,0)<0)continue;
        unsigned type=st.st_mode&0170000;
        if(type==0020000) {
            struct termios settings;
            if(raw_syscall(__NR_ioctl,fd,TCGETS,(long)&settings,0,0,0)<0)continue;
        } else if(type!=0010000)continue; /* FIFO/pipe or verified TTY only. */
        long flags=raw_syscall(__NR_fcntl,fd,F_GETFL,0,0,0,0);
        long descriptor=raw_syscall(__NR_fcntl,fd,F_GETFD,0,0,0,0);
        if(flags<0 || descriptor<0 || (flags&O_PATH) || (flags&O_ACCMODE)==O_RDONLY)continue;
        /* New IDs exceed the restored serial; imported aliases cannot forge a
         * grant by claiming the same description in an unauthenticated blob. */
        int rc=fd_table_open(table,fd,(struct fd_origin){0,FD_ACCESS_UNKNOWN},!!(descriptor&FD_CLOEXEC));
        if(rc)return rc;
        s->stdio_output[fd-1]=fd_table_get(table,fd)->description;
    }
    return 0;
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
            if(g_payload_config.revalidate_file_fds) {
                struct proot_open_origin observed={0,false};
                if(!proot_revalidate_regular_fd(record->fd,&observed) && observed.known)
                    record->origin=(struct fd_origin){observed.mount_id,FD_ACCESS_RW};
            }
        }
        raw_syscall(__NR_close,transport,0,0,0,0,0);
        g_payload_config.fd_state=-1;
        if(rc) {
            s->init_error=rc;
            __atomic_store_n(&s->initialized,3,__ATOMIC_RELEASE);
            return rc;
        }
    }
    if(g_payload_config.revalidate_file_fds) {
        /* exec does not carry cwd provenance; re-derive it like file FDs so
         * relative paths keep a known origin. Failure leaves cwd unknown. */
        struct proot_open_origin cwd;
        if(!proot_revalidate_cwd(&cwd))s->cwd=cwd;
    }
    int admission=admit_stdio_output(s);
    if(admission) {
        s->init_error=admission;
        __atomic_store_n(&s->initialized,3,__ATOMIC_RELEASE);
        return admission;
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
int fd_experiment_mount_access(enum fs_access access[CONFIG_MAX_BINDS+1], size_t *count)
{
    const char *v=g_payload_config.mount_access_observe;
    if(!v[0])return -ENODATA;
    size_t n=0;
    for(;n<CONFIG_MAX_BINDS+1 && v[n];n++) {
        if(v[n]!='d' && v[n]!='r' && v[n]!='w')return -EINVAL;
        access[n]=v[n]=='d'?FS_DENY:v[n]=='r'?FS_READ_ONLY:FS_READ_WRITE;
    }
    if(v[n])return -EINVAL;
    struct fs_policy policy={access,n};
    int valid=fs_policy_validate(&policy,g_payload_config.bind_count);
    if(valid)return valid;
    *count=n;return 0;
}
static int mount_decision(size_t mount, bool known, enum fs_operation operation)
{
    enum fs_access access[CONFIG_MAX_BINDS+1];
    size_t count;
    int rc=fd_experiment_mount_access(access,&count);
    if(rc)return rc;
    struct fs_policy policy={access,count};
    return fs_policy_check(&policy,mount,known,operation);
}
int fd_experiment_check_path_mutation(size_t mount, bool known)
{
    if(!g_payload_config.guard_path_mutations)return 0;
    return mount_decision(mount,known,FS_MUTATE);
}
/* File-content and metadata mutations only. No syscall, allocation or path
 * lookup in this check. Kernel still owns the actual IO and access-mode checks.
 * Unknown inherited/imported/non-file FDs have no implicit write grant. */
static int check_fd_mutation(struct fd_table *t, struct fd_runtime *s, long n, long a[6])
{
    if(g_payload_config.guard_path_mutations != 2)return 0;
    int fd;
    switch(n) {
    case __NR_write: case __NR_writev: case __NR_pwrite64:
    case __NR_pwritev: case __NR_pwritev2:
    case __NR_ftruncate: case __NR_fallocate:
    case __NR_fchmod: case __NR_fchown:
    case __NR_fsetxattr: case __NR_fremovexattr:
    case __NR_sendfile: case __NR_vmsplice:
        fd=(int)a[0];break;
    case __NR_tee:
        fd=(int)a[1];break;
    case __NR_copy_file_range: case __NR_splice:
        fd=(int)a[2];break;
    case __NR_faccessat2:
        if(!((unsigned int)a[2]&2))return 0; /* W_OK only, not read visibility. */
        if(((unsigned int)a[2]&~7u) ||
           ((unsigned int)a[3]&~(AT_EACCESS|AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH)))
            return -EINVAL;
        if(!a[1] || ((const char *)a[1])[0] || !(a[3]&AT_EMPTY_PATH))return 0;
        fd=(int)a[0];break;
    case __NR_utimensat:
        if(a[1])return 0; /* Non-null paths use the PRoot guard. */
        fd=(int)a[0];break;
    case __NR_fchownat:
        if(!a[1] || ((const char *)a[1])[0] || !(a[4]&AT_EMPTY_PATH))return 0;
        fd=(int)a[0];break;
    default:return 0;
    }
    if(fd==AT_FDCWD && (n==__NR_utimensat || n==__NR_fchownat || n==__NR_faccessat2))
        return mount_decision(s->cwd.mount_id,s->cwd.known,FS_MUTATE);
    const struct fd_record *r=fd_table_get(t,fd);
    if((n==__NR_write || n==__NR_writev) && r && r->description &&
       (r->description==s->stdio_output[0] || r->description==s->stdio_output[1]))return 0;
    if(g_payload_config.allow_pipe_output && r && r->pipe_writer &&
       (n==__NR_write || n==__NR_writev || n==__NR_sendfile || n==__NR_splice ||
        n==__NR_tee || n==__NR_vmsplice || n==__NR_copy_file_range))return 0;
    return mount_decision(r?r->origin.mount_id:0,
                          r && r->origin.access!=FD_ACCESS_UNKNOWN,FS_MUTATE);
}
/* Content reads in file access mode. Known file origins follow the mount
 * policy; locally created non-file objects carry a stream grant. Unknown
 * (inherited/imported/exec-restored) FDs are denied unless stream input is
 * explicitly allowed and the kernel object is a pipe, socket or a terminal
 * that answers TCGETS. Invalid FDs keep EBADF ahead of policy. */
static int check_fd_read(struct fd_table *t, int fd)
{
    const struct fd_record *r=fd_table_get(t,fd);
    if(r && r->stream_reader)return 0;
    if(r && r->origin.access!=FD_ACCESS_UNKNOWN)
        return mount_decision(r->origin.mount_id,true,FS_OBSERVE);
    struct stat st;
    long rc=raw_syscall(__NR_fstat,fd,(long)&st,0,0,0,0);
    if(rc<0)return (int)rc;
    if(!g_payload_config.allow_stream_input)return -EACCES;
    unsigned type=st.st_mode&0170000;
    if(type==0010000 || type==0140000)return 0;
    if(type!=0020000)return -EACCES;
    struct termios term;
    return raw_syscall(__NR_ioctl,fd,TCGETS,(long)&term,0,0,0)<0 ? -EACCES : 0;
}
static int check_read_call(struct fd_table *t, long n, long a[6])
{
    if(!g_payload_config.guard_file_reads)return 0;
    switch(n) {
    case __NR_read: case __NR_readv: case __NR_pread64:
    case __NR_preadv: case __NR_preadv2:
    case __NR_splice: case __NR_tee: case __NR_copy_file_range:
    case __NR_fgetxattr: case __NR_flistxattr:
        return check_fd_read(t,(int)a[0]);
    case __NR_sendfile:
        return check_fd_read(t,(int)a[1]);
    case __NR_mmap:
        /* Private file mappings read content too, not just shared ones. */
        return (a[3]&MAP_ANONYMOUS) ? 0 : check_fd_read(t,(int)a[4]);
    case __NR_readlinkat:
        /* Empty path reads the target of an O_PATH symlink FD itself. */
        if(!a[1] || ((const char *)a[1])[0])return 0;
        return check_fd_read(t,(int)a[0]);
    default:return 0;
    }
}

/* Only audited fcntl families are admitted in file-mutation mode. Advisory
 * locks do not grant content access: known visible sources may lock, while
 * access mode and flock validation remain the kernel's responsibility. */
static int check_fcntl(struct fd_table *t, long a[6])
{
    if(g_payload_config.guard_path_mutations!=2)return 0;
    enum fs_operation operation;
    switch(a[1]) {
    case F_DUPFD: case F_DUPFD_CLOEXEC: case F_GETFD: case F_SETFD:
    case F_GETFL: case F_GETOWN: case F_GETOWN_EX: case F_GETSIG:
    case F_GETLEASE: case F_GET_SEALS:
    case F_GETPIPE_SZ: case F_SETPIPE_SZ:
    case F_GET_RW_HINT: case F_GET_FILE_RW_HINT:
        return 0;
    case F_SETFL:
        /* Async signal ownership/notification is not admitted in this mode. */
        return a[2]&O_ASYNC ? -EOPNOTSUPP : 0;
    case F_GETLK: case F_SETLK: case F_SETLKW:
    case F_OFD_GETLK: case F_OFD_SETLK: case F_OFD_SETLKW:
        operation=FS_OBSERVE;break;
    case F_SET_RW_HINT: case F_SET_FILE_RW_HINT:
        operation=FS_MUTATE;break;
    default:
        /* Includes lease/notification/owner setters, seal mutation and new
         * commands; no kernel call or user-pointer access before rejection. */
        return -EOPNOTSUPP;
    }
    const struct fd_record *r=fd_table_get(t,(int)a[0]);
    return mount_decision(r?r->origin.mount_id:0,
                          r && r->origin.access!=FD_ACCESS_UNKNOWN,operation);
}

/* ioctl numbers do not describe their effects (nor all affected FDs).
 * Keep a small explicit command/type set in file-mutation mode. Never infer
 * safety from _IOC_READ/_IOC_WRITE: those bits describe argument copying. */
static int check_ioctl(struct fd_table *t, long a[6])
{
    if(g_payload_config.guard_path_mutations!=2)return 0;
    unsigned request=(unsigned)a[1];
    switch(request) {
    case FIOCLEX: case FIONCLEX: case FIONBIO:
        return 0; /* Generic descriptor/status controls; CLOEXEC tracked below. */
    case TIOCGPTPEER:
        return -ENOSYS; /* Existing unsupported FD-creation contract. */
    case FS_IOC_SETFLAGS: case FS_IOC_SETVERSION: case FS_IOC_FSSETXATTR: {
        const struct fd_record *r=fd_table_get(t,(int)a[0]);
        int rc=mount_decision(r?r->origin.mount_id:0,
                             r && r->origin.access!=FD_ACCESS_UNKNOWN,FS_MUTATE);
        if(rc)return rc;
        break;
    }
    case FS_IOC_GETFLAGS: case FS_IOC_GETVERSION: case FS_IOC_FSGETXATTR:
    case FIONREAD: case TCGETS: case TIOCGWINSZ: case TIOCGPGRP:
        break;
    default:
        /* Includes clone/dedupe's embedded descriptors, terminal injection,
         * device-specific mutations and unknown/new command numbers. */
        return -EOPNOTSUPP;
    }
    struct stat st;
    long rc=raw_syscall(__NR_fstat,a[0],(long)&st,0,0,0,0);
    if(rc<0)return rc;
    unsigned type=st.st_mode&0170000;
    if(request==FIONREAD) {
        if(type==0100000 || type==0010000 || type==0140000)return 0;
    } else if(request!=TCGETS && request!=TIOCGWINSZ && request!=TIOCGPGRP) {
        return type==0100000 || type==0040000 ? 0 : -EOPNOTSUPP;
    }
    /* Require a character FD with a successful native terminal query. */
    if(type!=0020000)return -EOPNOTSUPP;
    struct termios term;
    rc=raw_syscall(__NR_ioctl,a[0],TCGETS,(long)&term,0,0,0);
    return rc<0 ? (int)rc : 0;
}

static int mapping_range(long address, long length, uintptr_t *end)
{
    size_t page=0;
    for(size_t i=0;i+1<g_payload_config.guest_auxv_bytes/sizeof(uint64_t) &&
                      i+1<CONFIG_AUXV_PAIRS*2;i+=2)
        if(g_payload_config.guest_auxv[i]==AT_PAGESZ)page=g_payload_config.guest_auxv[i+1];
    if(!page || (page&(page-1)))return -EOPNOTSUPP;
    uintptr_t begin=(uintptr_t)address, len=(uintptr_t)length;
    if(begin&(page-1))return -EINVAL;
    if(!len || len>UINTPTR_MAX-(page-1))return -EINVAL;
    len=(len+page-1)&~(page-1);
    if(begin>UINTPTR_MAX-len)return -EINVAL;
    *end=begin+len;return 0;
}
/* All admitted shared file mappings require mutation rights even when first
 * mapped read-only; later mprotect cannot introduce an unchecked file writer.
 * Private/COW and anonymous mappings cannot write back to a file. */
static long guarded_mapping(struct fd_runtime *s, struct fd_table *t, long n, long a[6])
{
    /* vfork shares VM but uses a private FD arena. Do not publish divergent
     * mapping records until shared-VM lifecycle accounting exists. */
    if(vfork_active)return -EOPNOTSUPP;
    if(n==__NR_pkey_mprotect)return -ENOSYS;
    if(n==__NR_mremap) {
        long result=syscall_handle_common(n,a);
        /* Remap/alias flags need no incorrect address inference: discard all
         * admissions after success; subsequent upgrades must fail closed. */
        if((unsigned long)result<(unsigned long)-4095)s->mappings.count=0;
        return result;
    }
    if(n==__NR_mprotect && !a[1])return syscall_handle_common(n,a);
    uintptr_t end;
    int rc=mapping_range(n==__NR_mmap?0:a[0],a[1],&end);
    if(rc)return rc;
    if(n==__NR_mmap) {
        unsigned long type=(unsigned long)a[3]&MAP_TYPE;
        if(type!=MAP_PRIVATE && type!=MAP_SHARED && type!=MAP_SHARED_VALIDATE)return -EINVAL;
        if(!(a[3]&MAP_ANONYMOUS) && type!=MAP_PRIVATE) {
            const struct fd_record *r=fd_table_get(t,(int)a[4]);
            rc=mount_decision(r?r->origin.mount_id:0,
                             r && r->origin.access!=FD_ACCESS_UNKNOWN,FS_MUTATE);
            if(rc)return rc;
            /* The legacy executable-file fallback produces an anonymous copy,
             * which must not silently replace shared-file semantics here. */
            if(a[2]&PROT_EXEC)return -EOPNOTSUPP;
        }
        /* One possible new disjoint interval. Reserve before changing VM. */
        if(s->mappings.count==VM_WRITE_REGIONS)return -ENOSPC;
        long result=syscall_handle_common(n,a);
        if((unsigned long)result<(unsigned long)-4095) {
            uintptr_t finish;
            rc=mapping_range(result,a[1],&finish);
            if(rc || vm_write_add(&s->mappings,(uintptr_t)result,finish))
                s->mappings.count=0; /* Cannot grant using incomplete metadata. */
        }
        return result;
    }
    if(n==__NR_munmap) {
        struct vm_write_guard next=s->mappings;
        rc=vm_write_remove(&next,(uintptr_t)a[0],end);
        if(rc)return rc; /* A split may require one additional interval. */
        long result=syscall_handle_common(n,a);
        if(result==0)s->mappings=next;
        return result;
    }
    /* Executable upgrades also patch instructions, so they need admitted VM. */
    if((n==__NR_mprotect && (a[2]&(PROT_WRITE|PROT_EXEC))) ||
       (n==__NR_madvise && a[2]==MADV_REMOVE))
        if(!vm_write_covers(&s->mappings,(uintptr_t)a[0],end))return -EACCES;
    return syscall_handle_common(n,a);
}
long fd_experiment_dispatch(long n,long a[6])
{
    struct fd_runtime *s=current();
    int rc=start(s);if(rc)return rc;
    struct fd_table *t=fd_registry_table(&s->registry,s->owner);
    /* No request/context ownership model exists for asynchronous IO. Deny
     * the whole family before reading guest structures or reaching the kernel,
     * including operations on inherited rings/contexts. Slow routing alone
     * does not authorize an iocb's FD or protect its completion lifetime. */
    if(g_payload_config.guard_path_mutations==2) {
        switch(n) {
        case __NR_io_setup: case __NR_io_destroy:
        case __NR_io_submit: case __NR_io_cancel:
        case __NR_io_getevents: case __NR_io_pgetevents:
        case __NR_io_uring_setup: case __NR_io_uring_enter: case __NR_io_uring_register:
            return -ENOSYS;
        }
    }
    /* Not bridged: the raw guest path would reach the host and reveal
     * existence/identity of hidden names. Handles have no read model. */
    if(g_payload_config.guard_file_reads && n==__NR_name_to_handle_at)return -ENOSYS;
    if(n==__NR_prctl && a[0]==PR_ELF_FD_QUERY) {
        /* Diagnostic only: decision for a supplied mount ID, not an FD grant. */
        if(a[1]==6) {
            return mount_decision((size_t)a[2],true,(enum fs_operation)a[3]);
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
    /* advice is an int in the kernel ABI. Normalize before deciding whether
     * MADV_REMOVE needs mapping authorization; high bits cannot hide a punch. */
    if(n==__NR_madvise)a[2]=(int)a[2];
    /* Content sources, including private file mappings, before any mapping
     * bookkeeping or transfer destination checks. */
    rc=check_read_call(t,n,a);if(rc<0)return rc;
    if(g_payload_config.guard_path_mutations==2 &&
       (n==__NR_mmap || n==__NR_mprotect || n==__NR_munmap || n==__NR_mremap ||
        n==__NR_pkey_mprotect || (n==__NR_madvise && a[2]==MADV_REMOVE)))
        return guarded_mapping(s,t,n,a);
    /* Linux consumes unsigned int cmd. Normalize before both authorization
     * and FD-event classification, or high bits can hide dup/setfd effects. */
    if(n==__NR_fcntl) {
        a[1]=(unsigned int)a[1];
        rc=check_fcntl(t,a);if(rc<0)return rc;
    }
    rc=check_fd_mutation(t,s,n,a);if(rc<0)return rc;
    if(n==__NR_getdents64 && g_payload_config.guard_file_reads) {
        const struct fd_record *r=fd_table_get(t,(int)a[0]);
        struct proot_open_origin anchor={0,false};
        if(r && r->origin.access!=FD_ACCESS_UNKNOWN)
            anchor=(struct proot_open_origin){r->origin.mount_id,true};
        return proot_getdents_visible((int)a[0],(void *)a[1],(unsigned int)a[2],&anchor);
    }
    if(n==__NR_ioctl) { rc=check_ioctl(t,a);if(rc<0)return rc; }
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
    /* Non-file objects created here hold no mount content. */
    int stream=pair || n==__NR_memfd_create || n==__NR_eventfd2 || n==__NR_epoll_create1 ||
        n==__NR_timerfd_create || n==__NR_socket || n==__NR_accept || n==__NR_accept4 ||
        n==__NR_inotify_init1 || n==__NR_signalfd4;
    if(pair) {
        /* Read only after kernel success. This relies on the experimental
         * single-task AArch64 address space and nested slow-call exclusion;
         * it is not a general user-memory snapshot for concurrent guests. */
        const int *fds=(const int *)a[n==__NR_pipe2?0:3];
        int first=fds[0],second=fds[1];
        rc=fd_table_open(t,first,(struct fd_origin){0,FD_ACCESS_UNKNOWN},!!(a[1]&O_CLOEXEC));
        if(!rc)rc=(n==__NR_pipe2 && g_payload_config.allow_pipe_output &&
                   g_payload_config.guard_path_mutations==2)?
            fd_table_open_pipe_writer(t,second,!!(a[1]&O_CLOEXEC)):
            fd_table_open(t,second,(struct fd_origin){0,FD_ACCESS_UNKNOWN},!!(a[1]&O_CLOEXEC));
        if(!rc)rc=fd_table_grant_stream(t,first);
        if(!rc)rc=fd_table_grant_stream(t,second);
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
        if(!rc && stream)rc=fd_table_grant_stream(t,(int)result);
    }
    else if(setfd)rc=fd_table_set_cloexec(t,(int)a[0],ioctl_setfd?(unsigned)a[1]==FIOCLEX:!!(a[2]&FD_CLOEXEC));
    else rc=fd_table_dup(t,(int)a[0],(int)result,n==__NR_dup3?!!(a[2]&O_CLOEXEC):n==__NR_fcntl && a[1]==F_DUPFD_CLOEXEC);
    /* Preflight plus single-task exclusion guarantees capacity/serial here. */
    if(rc)return rc;
    return result;
}
