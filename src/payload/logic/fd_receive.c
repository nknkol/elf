/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include "fd_receive.h"
#define RECEIVE_MAX 128
#define RECEIVE_BATCH_MAX 8
struct receive_buffer {
    struct msghdr input;
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(RECEIVE_MAX*sizeof(int))]; } control;
};
extern long raw_syscall(long,long,long,long,long,long,long);
/* Kernel-checked copying; never fall back to unchecked guest loads/stores. */
static int transfer(void *local,void *guest,size_t bytes,int write)
{
    if(!bytes)return 0;
    struct iovec l={local,bytes},r={guest,bytes};
    long pid=raw_syscall(__NR_getpid,0,0,0,0,0,0);
    long n=raw_syscall(write?__NR_process_vm_writev:__NR_process_vm_readv,
                       pid,(long)&l,1,(long)&r,1,0);
    return n==(long)bytes?0:n<0?(int)n:-EFAULT;
}
static int prepare(struct receive_buffer *buffer,struct msghdr *message,void *guest,size_t *bound)
{
    int rc=transfer(&buffer->input,guest,sizeof(buffer->input),0);
    if(rc)return rc;
    size_t length=buffer->input.msg_control?buffer->input.msg_controllen:0;
    if(length>sizeof(buffer->control.bytes))return -ENOSPC;
    /* Padding can hold another descriptor. Other headers only reduce count. */
    *bound+=length>=CMSG_LEN(0)?(length-CMSG_LEN(0))/sizeof(int):0;
    memset(&buffer->control,0,sizeof(buffer->control));
    *message=buffer->input;
    message->msg_control=buffer->input.msg_control?buffer->control.bytes:NULL;
    message->msg_controllen=length;
    return 0;
}
static int reserve(struct fd_table *table,size_t bound,const struct fd_receive_sync *sync)
{
    sync->lock(sync->context);
    size_t available=0;
    for(size_t i=0;i<table->capacity;i++)available+=table->slots[i].fd<0;
    available=available>*sync->reserved?available-*sync->reserved:0;
    int rc=bound>RECEIVE_MAX || bound>available?-ENOSPC:
        bound>UINT64_MAX-table->serial?-EOVERFLOW:0;
    if(!rc)*sync->reserved+=bound;
    sync->unlock(sync->context);
    return rc;
}
static void release(size_t bound,const struct fd_receive_sync *sync)
{
    sync->lock(sync->context);
    *sync->reserved-=bound;
    sync->unlock(sync->context);
}
static size_t collect(struct receive_buffer *buffer,struct msghdr *message,int *received)
{
    size_t count=0;
    /* Only parse kernel output in private storage. Its total FD count is
     * bounded by the preflight control length, across all messages. */
    for(size_t offset=0;offset+sizeof(struct cmsghdr)<=message->msg_controllen;) {
        struct cmsghdr header;memcpy(&header,buffer->control.bytes+offset,sizeof(header));
        if(header.cmsg_len<CMSG_LEN(0) || header.cmsg_len>message->msg_controllen-offset)break;
        if(header.cmsg_level==SOL_SOCKET && header.cmsg_type==SCM_RIGHTS) {
            size_t n=(header.cmsg_len-CMSG_LEN(0))/sizeof(int);
            memcpy(received+count,buffer->control.bytes+offset+CMSG_LEN(0),n*sizeof(int));
            count+=n;
        }
        offset+=CMSG_ALIGN(header.cmsg_len);
    }
    return count;
}
static int output(struct receive_buffer *buffer,struct msghdr *message,void *guest)
{
    int rc=transfer(buffer->control.bytes,buffer->input.msg_control,message->msg_controllen,1);
#define OUTPUT(field) if(!rc)rc=transfer(&message->field,(char *)guest+offsetof(struct msghdr,field),sizeof(message->field),1)
    OUTPUT(msg_namelen);OUTPUT(msg_controllen);OUTPUT(msg_flags);
#undef OUTPUT
    return rc;
}
static void discard(int *received,size_t count)
{
    for(size_t i=0;i<count;i++)raw_syscall(__NR_close,received[i],0,0,0,0,0);
}
static int import(struct fd_table *table,int *received,size_t count,long flags,
                  const struct fd_receive_sync *sync)
{
    int rc=0;
    sync->lock(sync->context);
    for(size_t i=0;!rc && i<count;i++)
        rc=fd_table_import_unknown(table,received[i],!!(flags&MSG_CMSG_CLOEXEC));
    sync->unlock(sync->context);
    return rc; /* The reservation guarantees room. */
}
long fd_receive_message(struct fd_table *table,long a[6],const struct fd_receive_sync *sync)
{
    struct receive_buffer buffer;struct msghdr message;size_t bound=0;
    int rc=prepare(&buffer,&message,(void *)a[1],&bound);
    if(!rc)rc=reserve(table,bound,sync);
    if(rc)return rc;
    long result=raw_syscall(__NR_recvmsg,a[0],(long)&message,a[2],0,0,0);
    if(result<0) { release(bound,sync);return result; }
    int received[RECEIVE_MAX];size_t count=collect(&buffer,&message,received);
    rc=output(&buffer,&message,(void *)a[1]);
    if(rc) { discard(received,count);release(bound,sync);return rc; }
    rc=import(table,received,count,a[2],sync);
    release(bound,sync);
    return rc?rc:result;
}
long fd_receive_messages(struct fd_table *table,long a[6],const struct fd_receive_sync *sync)
{
    unsigned length=(unsigned)a[2];
    if(!length)return raw_syscall(__NR_recvmmsg,a[0],a[1],0,a[3],a[4],0);
    if(length>RECEIVE_BATCH_MAX)return -E2BIG;
    struct receive_buffer buffers[RECEIVE_BATCH_MAX];
    struct mmsghdr messages[RECEIVE_BATCH_MAX];
    size_t bound=0;int rc;
    for(unsigned i=0;i<length;i++) {
        rc=prepare(&buffers[i],&messages[i].msg_hdr,
                   (char *)a[1]+i*sizeof(struct mmsghdr),&bound);
        if(rc)return rc;
        messages[i].msg_len=0;
    }
    rc=reserve(table,bound,sync);if(rc)return rc;
    struct timespec timeout;
    if(a[4]) {
        rc=transfer(&timeout,(void *)a[4],sizeof(timeout),0);
        if(rc) { release(bound,sync);return rc; }
    }
    /* Keep timeout and headers local so post-receive output faults cannot hide
     * the kernel's completed message count and the installed descriptors. */
    long result=raw_syscall(__NR_recvmmsg,a[0],(long)messages,length,a[3],a[4]?(long)&timeout:0,0);
    if(result<0) { release(bound,sync);return result; }
    int received[RECEIVE_MAX];size_t offsets[RECEIVE_BATCH_MAX+1]={0};
    for(long i=0;i<result;i++)
        offsets[i+1]=offsets[i]+collect(&buffers[i],&messages[i].msg_hdr,received+offsets[i]);
    if(a[4]) {
        rc=transfer(&timeout,(void *)a[4],sizeof(timeout),1);
        if(rc) { discard(received,offsets[result]);release(bound,sync);return rc; }
    }
    for(long i=0;i<result;i++) {
        char *guest=(char *)a[1]+i*sizeof(struct mmsghdr);
        rc=output(&buffers[i],&messages[i].msg_hdr,guest);
        if(!rc)rc=transfer(&messages[i].msg_len,guest+offsetof(struct mmsghdr,msg_len),sizeof(messages[i].msg_len),1);
        if(rc) {
            /* Preserve the published prefix. Later kernel-received messages
             * may already be consumed: close every unpublished descriptor. */
            discard(received+offsets[i],offsets[result]-offsets[i]);
            release(bound,sync);
            return i?i:rc;
        }
        rc=import(table,received+offsets[i],offsets[i+1]-offsets[i],a[3],sync);
        if(rc) { release(bound,sync);return rc; }
    }
    release(bound,sync);
    return result;
}
