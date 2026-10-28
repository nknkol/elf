/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include "fd_experiment.h"
#include "fd_table.h"
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long query(int selector,int fd) { return call(__NR_prctl,PR_ELF_FD_QUERY,selector,fd,0); }

static long open_file(const char *path,long flags)
{ return call(__NR_openat,AT_FDCWD,(long)path,flags,0); }
static void origin(long fd,long mount,long access)
{ CHECK(fd>=0);CHECK(query(4,fd)==mount && query(5,fd)==access); }
static void close_fd(long fd) { CHECK(call(__NR_close,fd,0,0,0)==0); }
void run(long *stack)
{
    if(stack[0]==2) {
        const char *value=(const char *)stack[2];int fd=0;
        while(*value)fd=fd*10+*value++-'0';
        /* Seals do not authenticate policy. Existing exec import must still
         * discard the newly populated source tags. */
        origin(fd,0,FD_ACCESS_UNKNOWN);close_fd(fd);
        static const char pass[]="PASS: runtime FD mount origins, bind aliases, dup/fork and exec downgrade\n";
        call(__NR_write,1,(long)pass,sizeof(pass)-1,0);call(__NR_exit_group,0,0,0,0);for(;;){}
    }
    long base=query(0,0);
    long a=open_file("/one/file",O_RDONLY),b=open_file("/two/file",O_RDONLY);
    origin(a,1,FD_ACCESS_RW);origin(b,2,FD_ACCESS_RW);
    CHECK(query(2,a)!=query(2,b));
    char byte=0;CHECK(call(__NR_read,a,(long)&byte,1,0)==1 && byte=='Q');
    CHECK(call(__NR_read,b,(long)&byte,1,0)==1 && byte=='Q');
    long root=open_file("/fd-data",O_RDONLY);origin(root,0,FD_ACCESS_RW);
    long link=open_file("/one/to-two",O_RDONLY);origin(link,2,FD_ACCESS_RW);
    long nofollow=open_file("/one/to-two",O_PATH|O_NOFOLLOW);origin(nofollow,1,FD_ACCESS_RW);
    long nested=open_file("/one/nested/value",O_RDONLY);origin(nested,3,FD_ACCESS_RW);
    long shadow=open_file("/shadow/file",O_RDONLY);origin(shadow,5,FD_ACCESS_RW);
    unsigned long how[3]={O_PATH|O_NOFOLLOW|O_CLOEXEC,0,0};
    long newer=call(437,AT_FDCWD,(long)"/two/file",(long)how,sizeof(how));
    origin(newer,2,FD_ACCESS_RW);CHECK(query(3,newer)==1);
    long directory=open_file("/one",O_PATH|O_DIRECTORY);origin(directory,1,FD_ACCESS_RW);
    long relative=call(__NR_openat,directory,(long)"file",O_RDONLY,0);origin(relative,1,FD_ACCESS_RW);
    long otherdir=open_file("/two",O_PATH|O_DIRECTORY);origin(otherdir,2,FD_ACCESS_RW);
    long fromone=call(__NR_openat,directory,(long)"nested/value",O_RDONLY,0);
    long fromtwo=call(__NR_openat,otherdir,(long)"nested/value",O_RDONLY,0);
    origin(fromone,3,FD_ACCESS_RW);origin(fromtwo,2,FD_ACCESS_RW);
    CHECK(call(__NR_read,fromone,(long)&byte,1,0)==1 && byte=='N');
    CHECK(call(__NR_read,fromtwo,(long)&byte,1,0)==1 && byte=='S');
    close_fd(fromone);close_fd(fromtwo);
    long dircopy=call(__NR_dup,directory,0,0,0);origin(dircopy,1,FD_ACCESS_RW);
    fromone=call(__NR_openat,dircopy,(long)"nested/value",O_RDONLY,0);
    origin(fromone,3,FD_ACCESS_RW);close_fd(fromone);close_fd(dircopy);
    long moving=open_file("/one/moving",O_PATH|O_DIRECTORY);origin(moving,1,FD_ACCESS_RW);
    CHECK(call(__NR_renameat,directory,(long)"moving",directory,(long)"moved")==0);
    long moved=call(__NR_openat,moving,(long)"value",O_RDONLY,0);origin(moved,1,FD_ACCESS_RW);
    CHECK(call(__NR_read,moved,(long)&byte,1,0)==1 && byte=='M');close_fd(moved);
    unsigned long relative_how[3]={O_PATH|O_NOFOLLOW,0,0};
    moved=call(437,moving,(long)"value",(long)relative_how,sizeof(relative_how));
    origin(moved,1,FD_ACCESS_RW);close_fd(moved);
    /* Move through the other alias into an area hidden by /one/nested.
     * The old /one origin must reject, rather than switch to the overmount. */
    CHECK(call(__NR_renameat,otherdir,(long)"moved",otherdir,(long)"nested/shadow")==0);
    long before=query(0,0);
    CHECK(call(__NR_openat,moving,(long)"value",O_RDONLY,0)==-EXDEV && query(0,0)==before);
    close_fd(moving);close_fd(otherdir);
    moved=call(__NR_openat,directory,(long)"../fd-data",O_RDONLY,0);
    origin(moved,0,FD_ACCESS_RW);close_fd(moved);
    moved=call(__NR_openat,directory,(long)"to-two",O_RDONLY,0);
    origin(moved,2,FD_ACCESS_RW);close_fd(moved);
    long cwdrelative=open_file("fd-data",O_RDONLY);origin(cwdrelative,0,FD_ACCESS_UNKNOWN);close_fd(cwdrelative);
    long copied=call(__NR_dup,a,0,0,0);origin(copied,1,FD_ACCESS_RW);
    CHECK(query(2,copied)==query(2,a));
    long count=query(0,0);
    CHECK(open_file("/two/missing",O_RDONLY)==-ENOENT && query(0,0)==count);
    CHECK(call(__NR_renameat,directory,(long)"file",directory,(long)"renamed")==0);
    origin(a,1,FD_ACCESS_RW);origin(b,2,FD_ACCESS_RW);origin(copied,1,FD_ACCESS_RW);
    long pid=call(__NR_clone,17,0,0,0);CHECK(pid>=0);
    if(pid==0) {
        origin(a,1,FD_ACCESS_RW);origin(b,2,FD_ACCESS_RW);close_fd(a);
        call(__NR_exit_group,0,0,0,0);for(;;){}
    }
    int status=-1;CHECK(call(__NR_wait4,pid,(long)&status,0,0)==pid && status==0);
    origin(a,1,FD_ACCESS_RW);
    long closing[]={b,root,link,nofollow,nested,shadow,newer,directory,relative,copied};
    for(unsigned i=0;i<sizeof(closing)/sizeof(closing[0]);i++)close_fd(closing[i]);
    CHECK(query(0,0)==base+1);
    char digits[24],reverse[24];int n=0,k=0;long value=a;
    do { reverse[n++]='0'+value%10;value/=10; } while(value);
    while(n)digits[k++]=reverse[--n];digits[k]=0;
    const char *args[]={"/origin",digits,0};
    call(__NR_execve,(long)args[0],(long)args,0,0);CHECK(0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
