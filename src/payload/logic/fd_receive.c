/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include "fd_table.h"
#define RECEIVE_MAX 128
extern long raw_syscall(long,long,long,long,long,long,long);
/* Kernel-checked copying: invalid or partially mapped guest pointers must not
 * fault the payload. No process_vm permission fallback to unchecked loads. */
static int transfer(void *local,void *guest,size_t bytes,int write)
{
    if(!bytes)return 0;
    struct iovec l={local,bytes},r={guest,bytes};
    long pid=raw_syscall(__NR_getpid,0,0,0,0,0,0);
    long n=raw_syscall(write?__NR_process_vm_writev:__NR_process_vm_readv,
                       pid,(long)&l,1,(long)&r,1,0);
    return n==(long)bytes?0:n<0?(int)n:-EFAULT;
}
long fd_receive_message(struct fd_table *table,long a[6])
{
    struct msghdr input;
    int rc=transfer(&input,(void *)a[1],sizeof(input),0);
    if(rc)return rc;
    size_t length=input.msg_control?input.msg_controllen:0;
    /* Conservative upper bound, including padding usable for another int.
     * Multiple headers or non-rights messages can only reduce this count. */
    size_t bound=length>=CMSG_LEN(0)?(length-CMSG_LEN(0))/sizeof(int):0;
    size_t available=0;
    for(size_t i=0;i<table->capacity;i++)available+=table->slots[i].fd<0;
    if(bound>RECEIVE_MAX || bound>available)return -ENOSPC;
    if(bound>UINT64_MAX-table->serial)return -EOVERFLOW;
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(RECEIVE_MAX*sizeof(int))]; } control={0};
    if(length>sizeof(control.bytes))return -ENOSPC;
    struct msghdr message=input;
    message.msg_control=input.msg_control?control.bytes:NULL;
    message.msg_controllen=length;
    long result=raw_syscall(__NR_recvmsg,a[0],(long)&message,a[2],0,0,0);
    if(result<0)return result;
    int received[RECEIVE_MAX];size_t count=0;
    /* The control buffer is kernel output in private storage. User writes
     * cannot substitute descriptors between receipt and publication. */
    for(size_t offset=0;offset+sizeof(struct cmsghdr)<=message.msg_controllen;) {
        struct cmsghdr header;memcpy(&header,control.bytes+offset,sizeof(header));
        if(header.cmsg_len<CMSG_LEN(0) || header.cmsg_len>message.msg_controllen-offset)break;
        if(header.cmsg_level==SOL_SOCKET && header.cmsg_type==SCM_RIGHTS) {
            size_t n=(header.cmsg_len-CMSG_LEN(0))/sizeof(int);
            memcpy(received+count,control.bytes+offset+CMSG_LEN(0),n*sizeof(int));
            count+=n;
        }
        offset+=CMSG_ALIGN(header.cmsg_len);
    }
    rc=transfer(control.bytes,input.msg_control,message.msg_controllen,1);
    /* Write only kernel output fields, not the guest's pointer fields. */
#define OUTPUT(field) if(!rc)rc=transfer(&message.field,(char *)a[1]+offsetof(struct msghdr,field),sizeof(message.field),1)
    OUTPUT(msg_namelen);OUTPUT(msg_controllen);OUTPUT(msg_flags);
#undef OUTPUT
    if(rc) {
        /* Message/data may have been consumed, as with native EFAULT. Never
         * retain an installed descriptor after failed output publication. */
        for(size_t i=0;i<count;i++)raw_syscall(__NR_close,received[i],0,0,0,0,0);
        return rc;
    }
    for(size_t i=0;i<count;i++) {
        /* Unknown provenance: receipt does not establish sender mount rights
         * or a correspondence with another local open-description ID. */
        rc=fd_table_import_unknown(table,received[i],!!(a[2]&MSG_CMSG_CLOEXEC));
        if(rc)return rc; /* Preflight + single-task exclusion guarantee room. */
    }
    return result;
}
