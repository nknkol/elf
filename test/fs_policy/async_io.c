/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <linux/aio_abi.h>
#include <errno.h>
#include <time.h>
static long call(long n,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define C(n,a,b,c,d,e,f) call(__NR_##n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define CHECK(x) do { if(!(x)) { C(exit_group,__LINE__,0,0,0,0,0);for(;;){} } } while(0)
void run(long *stack)
{
    CHECK(stack[0]==3);
    const char *digits=(const char *)stack[2],*mode=(const char *)stack[3];long fd=0;
    while(*digits)fd=fd*10+*digits++-'0';
    char value[]="AIO!";
    aio_context_t context=0;
    struct iocb request={.aio_lio_opcode=IOCB_CMD_PWRITE,.aio_fildes=fd,
                         .aio_buf=(unsigned long)value,.aio_nbytes=4,.aio_offset=0};
    struct iocb *requests[]={&request};
    struct io_event event={0};
    struct timespec timeout={.tv_sec=1};
    if(mode[0]=='g') {
        /* A valid writable inherited FD has no file capability in this mode. */
        CHECK(C(write,fd,value,4,0,0,0)==-EACCES);
        CHECK(C(io_setup,1,&context,0,0,0,0)==-ENOSYS && context==0);
        CHECK(C(io_submit,context,1,requests,0,0,0)==-ENOSYS);
        CHECK(C(io_getevents,context,1,1,&event,&timeout,0)==-ENOSYS);
        CHECK(event.res==0 && event.obj==0 && event.data==0);
        long calls[]={__NR_io_setup,__NR_io_destroy,__NR_io_submit,__NR_io_cancel,
                      __NR_io_getevents,__NR_io_pgetevents,__NR_io_uring_setup,
                      __NR_io_uring_enter,__NR_io_uring_register};
        for(unsigned i=0;i<sizeof(calls)/sizeof(calls[0]);i++) {
            CHECK(call(calls[i],0,0,0,0,0,0)==-ENOSYS);
            /* Non-null invalid pointers must never be dereferenced. */
            CHECK(call(calls[i],fd,1,1,1,1,1)==-ENOSYS);
        }
    } else {
        long results[5]={0,-999,-999,-999,-999};
        results[0]=C(io_setup,1,&context,0,0,0,0);
        if(results[0]==0) {
            results[1]=C(io_submit,context,1,requests,0,0,0);
            if(results[1]==1) {
                results[2]=C(io_getevents,context,1,1,&event,&timeout,0);
                results[4]=event.res;
            }
            results[3]=C(io_destroy,context,0,0,0,0,0);
        }
        CHECK(C(write,1,results,sizeof(results),0,0,0)==sizeof(results));
    }
    C(exit_group,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\n mov x0,sp\n bl run\n");
