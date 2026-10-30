/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include "fd_runtime.h"
static long call(long n,long a,long b,long c,long d) {
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long query(int kind,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,kind,fd,0); }
static void finish(void) { call(__NR_exit_group,42,0,0,0);for(;;){} }
void run(void) {
    /* Adopt descendants so this test reaps every process it creates. */
    CHECK(call(__NR_prctl,36,1,0,0)==0); /* PR_SET_CHILD_SUBREAPER */
    long fd=call(__NR_memfd_create,(long)"orphan",0,0,0);CHECK(fd>=0);
    long generation=query(1,fd);
    int pipe[2];CHECK(call(__NR_pipe2,(long)pipe,0,0,0)==0);
    long child=call(__NR_clone,17,0,0,0);CHECK(child>=0);
    if(!child) {
        CHECK(call(__NR_close,pipe[0],0,0,0)==0);
        /* More generations than the 64 clone-notification slots. Every parent
         * exits without waiting; its descendant must preserve the FD lineage. */
        for(int i=0;i<80;i++) {
            CHECK(query(0,0)==2 && query(1,fd)==generation);
            long next=call(__NR_clone,17,0,0,0);CHECK(next>=0);
            if(next)finish();
        }
        CHECK(query(1,fd)==generation);
        CHECK(call(__NR_write,pipe[1],(long)"Y",1,0)==1);
        finish();
    }
    CHECK(call(__NR_close,pipe[1],0,0,0)==0);
    char result=0;CHECK(call(__NR_read,pipe[0],(long)&result,1,0)==1 && result=='Y');
    int count=0,status;
    for(;;) {
        long pid=call(__NR_wait4,-1,(long)&status,0,0);
        if(pid==-EINTR)continue;
        if(pid==-ECHILD)break;
        CHECK(pid>0 && status==(42<<8));count++;
    }
    CHECK(count==81 && query(0,0)==2 && query(1,fd)==generation);
    CHECK(call(__NR_close,pipe[0],0,0,0)==0 && call(__NR_close,fd,0,0,0)==0);
    CHECK(query(0,0)==0);
    static const char pass[]="PASS: runtime FD 80-generation orphan chain, preserved metadata and full reaping\n";
    call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start: bl run\n");
