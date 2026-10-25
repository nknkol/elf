/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "clone_notify.h"
#include "fd_clone.h"
extern long notify_clone(unsigned long,void *);
struct state {
    struct fd_table source, copy;
    struct fd_record source_slots[4], copy_slots[4];
    struct fd_clone transaction;
    int fd, ready, child_done, cleaned, share, child_first, reject;
    long tid;
};
static struct state *s;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f)
{ long r=syscall(n,a,b,c,d,e,f); return r==-1?-errno:r; }
int clone_observer_before(struct clone_event *event)
{
    assert(fd_clone_prepare(&s->transaction,&s->source,s->share?NULL:&s->copy,
                           s->share?FD_CLONE_SHARE:FD_CLONE_COPY)==0);
    event->cookie=&s->transaction;
    assert(fd_clone_lookup(&s->transaction,getpid())==NULL);
    return s->reject?-EACCES:0;
}
void clone_observer_finish(const struct clone_event *event,long result)
{
    struct fd_clone *t=event->cookie;
    assert(t==&s->transaction);
    if(result<0) { assert(fd_clone_lookup(t,getpid())==NULL);return; }
    if(result>0) {
        /* Deliberately change parent AFTER the kernel copy, before child reads. */
        assert(fcntl(s->fd,F_SETFD,FD_CLOEXEC)==0);
        assert(fd_table_set_cloexec(&s->source,s->fd,1)==0);
        if(!s->child_first)assert(fd_clone_publish(t,result)==0);
        __atomic_store_n(&s->ready,1,__ATOMIC_RELEASE);
        while(!__atomic_load_n(&s->child_done,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
        assert(fd_clone_publish(t,result)==0); /* duplicate registration */
        assert(fd_clone_publish(t,result+1)==-EEXIST);
        assert(fd_clone_lookup(t,result+1)==NULL);
        assert(fd_clone_lookup(t,result)==(s->share?&s->source:&s->copy));
        return;
    }
    while(!__atomic_load_n(&s->ready,__ATOMIC_ACQUIRE))syscall(SYS_sched_yield);
    long tid=syscall(SYS_gettid);
    assert(fd_clone_publish(t,tid)==0);
    struct fd_table *table=fd_clone_lookup(t,tid);assert(table);
    const struct fd_record *record=fd_table_get(table,s->fd);
    assert(record && record->origin.mount_id==73 && record->origin.access==FD_ACCESS_RO);
    assert(record->cloexec==s->share);
    assert(fcntl(s->fd,F_GETFD)==(s->share?FD_CLOEXEC:0));
    assert(close(s->fd)==0);fd_table_close(table,s->fd);
    s->tid=tid;
    __atomic_store_n(&s->child_done,1,__ATOMIC_RELEASE);
}
void clone_observer_cleanup(const struct clone_event *event,unsigned reasons)
{
    assert(event->cookie==&s->transaction);
    assert(reasons==(s->reject?CLONE_CLEANUP_REJECTED:0));
    assert(__atomic_add_fetch(&s->cleaned,1,__ATOMIC_ACQ_REL)==1);
    /* The child adopted the table: cookie retirement must not destroy it. */
}
static void run(unsigned long flags,int share,int child_first,void *stack)
{
    *s=(struct state){.share=share,.child_first=child_first};
    assert(fd_table_init(&s->source,s->source_slots,4)==0);
    assert(fd_table_init(&s->copy,s->copy_slots,4)==0);
    s->fd=open("/dev/null",O_RDONLY);assert(s->fd>=0);
    assert(fd_table_open(&s->source,s->fd,(struct fd_origin){73,FD_ACCESS_RO},0)==0);
    long child=notify_clone(flags,stack);assert(child>0);
    if(flags & CLONE_THREAD) {
        for(unsigned i=0;i<10000;i++) {
            if(syscall(SYS_tgkill,getpid(),child,0)==-1 && errno==ESRCH)break;
            usleep(100);
        }
        assert(syscall(SYS_tgkill,getpid(),child,0)==-1 && errno==ESRCH);
    } else {
        int status;assert(waitpid(child,&status,0)==child);
        assert(WIFEXITED(status) && WEXITSTATUS(status)==42);
    }
    assert(s->cleaned==1 && s->tid==child);
    assert(fd_clone_lookup(&s->transaction,child)==(share?&s->source:&s->copy));
    if(share) {
        assert(fd_table_get(&s->source,s->fd)==NULL);
        assert(fcntl(s->fd,F_GETFD)==-1 && errno==EBADF);
    } else {
        assert(fd_table_get(&s->source,s->fd)->cloexec==1);
        assert(fcntl(s->fd,F_GETFD)==FD_CLOEXEC);
        assert(close(s->fd)==0);
    }
}
int main(void)
{
    s=mmap(NULL,sizeof(*s),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    assert(s!=MAP_FAILED);
    void *stack=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(stack!=MAP_FAILED);
    const unsigned long flags[]={SIGCHLD,CLONE_FILES|SIGCHLD,CLONE_VM|SIGCHLD,
        CLONE_VM|CLONE_FILES|SIGCHLD,CLONE_THREAD|CLONE_VM|CLONE_SIGHAND|CLONE_FILES,
        CLONE_THREAD|CLONE_VM|CLONE_SIGHAND};
    for(unsigned i=0;i<6;i++)for(int first=0;first<2;first++)
        run(flags[i],i>=4,first,(char*)stack+65536);
    /* Failed preparation leaves the unpublished transaction unchanged. */
    struct fd_clone bad={0};
    assert(fd_clone_prepare(&bad,&s->source,&s->copy,FD_CLONE_SHARE)==-EINVAL);
    assert(bad.table==NULL && fd_clone_publish(&bad,1)==-EINVAL);
    assert(fd_clone_publish(&s->transaction,0)==-EINVAL);
    struct fd_table tiny;
    struct fd_record small[1];
    assert(fd_table_init(&tiny,small,1)==0);
    assert(fd_table_open(&s->source,100,(struct fd_origin){1,FD_ACCESS_RW},0)==0);
    assert(fd_table_open(&s->source,101,(struct fd_origin){2,FD_ACCESS_RO},1)==0);
    assert(fd_clone_prepare(&bad,&s->source,&tiny,FD_CLONE_COPY)==-ENOSPC);
    assert(bad.table==NULL && tiny.serial==0 && small[0].fd==-1);
    s->cleaned=0;s->reject=1;
    assert(notify_clone(SIGCHLD,(char*)stack+65536)==-EACCES && s->cleaned==1);
    s->cleaned=0;s->reject=0;
    assert(notify_clone(CLONE_THREAD,(char*)stack+65536)==-EINVAL && s->cleaned==1);
    puts("PASS: FD pre-clone snapshots and identity publication across six host clone modes, both notification orders, rejection and kernel failure");
    return 0;
}
