/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include "fd_table.h"
/* Explicit ordering: worker commits a newly reused descriptor while main's
 * already successful close is waiting to update metadata. No lock spans I/O. */
static struct fd_table table;
static pthread_mutex_t metadata=PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t closed, reopened;
static int fd, replacement;
static void barrier(pthread_barrier_t *b)
{ int rc=pthread_barrier_wait(b);assert(rc==0 || rc==PTHREAD_BARRIER_SERIAL_THREAD); }
static void *reuse(void *unused)
{
    (void)unused;
    barrier(&closed);
    assert(dup3(replacement,fd,O_CLOEXEC)==fd);
    assert(pthread_mutex_lock(&metadata)==0);
    assert(fd_table_open(&table,fd,(struct fd_origin){22,FD_ACCESS_RW},1)==0);
    assert(pthread_mutex_unlock(&metadata)==0);
    barrier(&reopened);
    return NULL;
}
int main(void)
{
    struct fd_record slots[4];assert(fd_table_init(&table,slots,4)==0);
    fd=open("/dev/null",O_RDONLY);assert(fd>=0);
    replacement=open("/dev/zero",O_RDONLY);assert(replacement>=0 && replacement!=fd);
    assert(fd_table_open(&table,fd,(struct fd_origin){11,FD_ACCESS_RO},0)==0);
    uint64_t old=fd_table_get(&table,fd)->generation;
    assert(pthread_barrier_init(&closed,NULL,2)==0);
    assert(pthread_barrier_init(&reopened,NULL,2)==0);
    pthread_t worker;assert(pthread_create(&worker,NULL,reuse,NULL)==0);
    assert(close(fd)==0);
    barrier(&closed);barrier(&reopened);
    assert(pthread_mutex_lock(&metadata)==0);
    assert(fd_table_close_generation(&table,fd,old)==-ESTALE);
    const struct fd_record *record=fd_table_get(&table,fd);
    assert(record && record->origin.mount_id==22 && record->cloexec==1);
    uint64_t current=record->generation;
    assert(fd_table_close_generation(&table,fd,0)==-ESTALE); /* previously unknown */
    assert(fd_table_get(&table,fd)->generation==current);
    assert(pthread_mutex_unlock(&metadata)==0);
    assert(pthread_join(worker,NULL)==0);
    char byte=1;assert(read(fd,&byte,1)==1 && byte==0); /* new kernel FD survived */
    assert(close(fd)==0);
    assert(fd_table_close_generation(&table,fd,current)==0);
    assert(fd_table_get(&table,fd)==NULL);
    assert(fd_table_close_generation(&table,fd,current)==0); /* idempotent absent */
    assert(fd_table_close_generation(&table,fd,0)==0);
    assert(fd_table_close_generation(&table,-1,current)==-EINVAL);
    assert(fd_table_close_generation(NULL,fd,current)==-EINVAL);
    /* Failed kernel close is not an instruction to remove a different record. */
    assert(close(fd)==-1 && errno==EBADF);
    assert(fd_table_get(&table,fd)==NULL);
    assert(close(replacement)==0);
    assert(pthread_barrier_destroy(&closed)==0 && pthread_barrier_destroy(&reopened)==0);
    puts("PASS: delayed close commit preserves concurrently reused FD and provenance; matching/unknown/absent generations checked");
    return 0;
}
