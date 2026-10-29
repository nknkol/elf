/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
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
    CHECK(stack[0]==4);
    const char *path=(const char *)stack[2],*mode=(const char *)stack[3],*variant=(const char *)stack[4];
    long fd=C(openat,AT_FDCWD,path,O_RDWR,0,0,0);CHECK(fd>=0);
    long address=C(mmap,0,PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    CHECK((unsigned long)address<(unsigned long)-4095);
    CHECK(*(volatile char *)address=='Z');
    /* A successful mremap currently drops all mapping admissions. The live
     * shared writable mapping remains, so a missed REMOVE check has effects. */
    CHECK(C(mremap,address,PAGE_SIZE,PAGE_SIZE,0,0,0)==address);
    unsigned long high=variant[0]=='h'?(1ul<<32):variant[0]=='s'?0xffffffff00000000ul:0;
    /* Non-mutating advice must retain its native low-32-bit interpretation. */
    CHECK(C(madvise,address,PAGE_SIZE,high|MADV_NORMAL,0,0,0)==0);
    CHECK(C(madvise,address,PAGE_SIZE,high|0xfffffffful,0,0,0)==-EINVAL);
    long result=C(madvise,address,PAGE_SIZE,high|MADV_REMOVE,0,0,0);
    CHECK(result==(mode[0]=='g'?-EACCES:0));
    CHECK(*(volatile char *)address==(mode[0]=='g'?'Z':0));
    CHECK(C(munmap,address,PAGE_SIZE,0,0,0,0)==0);
    CHECK(C(close,fd,0,0,0,0,0)==0);
    C(exit_group,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\n mov x0,sp\n bl run\n");
