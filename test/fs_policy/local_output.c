/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
static long call(long n,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define C(n,a,b,c,d,e,f) call(__NR_##n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define CHECK(x) do { if(!(x)) { C(exit_group,__LINE__,0,0,0,0,0);for(;;){} } } while(0)
#define INHERITED_SOCKET 10
static void exit_ok(void) { C(exit_group,0,0,0,0,0,0);for(;;){} }
void run(long *stack)
{
    CHECK(stack[0]>=2);const char *mode=(const char *)stack[2];
    char byte=0;unsigned long value=3;
    if(mode[0]=='c') {
        /* Grants are local to the creating image: exec clears them. */
        CHECK(C(write,11,"x",1,0,0,0)==-EACCES);
        CHECK(C(write,12,&value,8,0,0,0)==-EACCES);
        exit_ok();
    }
    int on=mode[1]=='n';
    long expect=on?1:-EACCES;
    int pair[2];CHECK(C(socketpair,AF_UNIX,SOCK_STREAM,0,pair,0,0)==0);
    CHECK(C(write,pair[0],"a",1,0,0,0)==expect);
    struct iovec io={(void *)"b",1};
    CHECK(C(writev,pair[0],&io,1,0,0,0)==expect);
    /* send/recv were never file mutations; reads of local objects stay open. */
    CHECK(C(sendto,pair[0],"c",1,0,0,0)==1);
    long event=C(eventfd2,0,0,0,0,0,0);CHECK(event>=0);
    CHECK(C(write,event,&value,8,0,0,0)==(on?8:-EACCES));
    long memory=C(memfd_create,"elf-local",1,0,0,0,0);CHECK(memory>=0);
    CHECK(C(ftruncate,memory,4096,0,0,0,0)==(on?0:-EACCES));
    long shared=C(mmap,0,4096,PROT_READ|PROT_WRITE,MAP_SHARED,memory,0);
    /* Inherited and pipe outputs keep their existing contracts. */
    CHECK(C(write,INHERITED_SOCKET,"i",1,0,0,0)==-EACCES);
    int pipefd[2];CHECK(C(pipe2,pipefd,0,0,0,0,0)==0);
    CHECK(C(write,pipefd[1],"p",1,0,0,0)==-EACCES);
    if(!on) {
        CHECK(shared==-EACCES);
        exit_ok();
    }
    CHECK(C(read,pair[1],&byte,1,0,0,0)==1 && byte=='a');
    CHECK(C(read,pair[1],&byte,1,0,0,0)==1 && byte=='b');
    CHECK(C(read,pair[1],&byte,1,0,0,0)==1 && byte=='c');
    value=0;CHECK(C(read,event,&value,8,0,0,0)==8 && value==3);
    CHECK(C(pwrite64,memory,"mem",3,0,0,0)==3);
    CHECK(shared>0 || shared<-4095);
    char *page=(char *)shared;
    CHECK(page[0]=='m');page[1]='Z';
    CHECK(C(pread64,memory,&byte,1,1,0,0)==1 && byte=='Z');
    CHECK(C(munmap,shared,4096,0,0,0,0)==0);
    /* Grants follow dup and private fork. */
    long copy=C(dup,pair[0],0,0,0,0,0);CHECK(copy>=0);
    CHECK(C(write,copy,"d",1,0,0,0)==1);
    long child=C(clone,17,0,0,0,0,0);CHECK(child>=0);
    if(child==0) {
        CHECK(C(write,pair[0],"f",1,0,0,0)==1);
        exit_ok();
    }
    int status=-1;CHECK(C(wait4,child,&status,0,0,0,0)==child && status==0);
    CHECK(C(read,pair[1],&byte,1,0,0,0)==1 && byte=='d');
    CHECK(C(read,pair[1],&byte,1,0,0,0)==1 && byte=='f');
    /* A file source may be sent to a local socket. */
    long file=C(openat,AT_FDCWD,"/rw/file",O_RDONLY,0,0,0);CHECK(file>=0);
    CHECK(C(sendfile,pair[0],file,0,4,0,0)==4);
    /* Keep a socket and an eventfd open across exec at fixed numbers. */
    CHECK(C(dup3,pair[0],11,0,0,0,0)==11 && C(dup3,event,12,0,0,0,0)==12);
    const char *args[]={"/probe","child",0};
    C(execve,args[0],args,0,0,0,0);CHECK(0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
