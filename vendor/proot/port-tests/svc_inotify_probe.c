/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/inotify.h>
static long sc(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { sc(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
void run(long *sp)
{
    CHECK(sp[0]==4);char **av=(void *)(sp+1);char mode=av[1][0];
    long fd=sc(__NR_inotify_init1,IN_NONBLOCK|IN_CLOEXEC,0,0,0);CHECK(fd>=0);
    unsigned mask=IN_MODIFY|IN_DELETE_SELF;
    if(mode=='n')mask|=IN_DONT_FOLLOW;
    if(mode=='d' || mode=='e')mask|=IN_ONLYDIR;
    long watch=sc(__NR_inotify_add_watch,fd,mode=='z'?0:(long)av[2],mask,0);
    int denied=mode=='n' && watch==-EACCES;
    if(denied) {}
    else if(mode=='e')CHECK(watch==-ENOTDIR);
    else if(mode=='m' || mode=='x')CHECK(watch==-ENOENT);
    else if(mode=='z')CHECK(watch==-EFAULT);
    else {
        CHECK(watch>=0);
        long file=sc(__NR_openat,AT_FDCWD,(long)av[3],O_WRONLY,0);CHECK(file>=0);
        char c='Q';CHECK(sc(__NR_write,file,(long)&c,1,0)==1 && sc(__NR_close,file,0,0,0)==0);
        union { struct inotify_event align;char bytes[512]; } events;
        long size=sc(__NR_read,fd,(long)&events,sizeof(events),0);
        if(mode=='n') {
            CHECK(size==-EAGAIN);
            CHECK(sc(__NR_unlinkat,AT_FDCWD,(long)av[2],0,0)==0);
            size=sc(__NR_read,fd,(long)&events,sizeof(events),0);
        }
        CHECK(size>0);unsigned seen=0;
        for(long offset=0;offset<size;) {
            struct inotify_event *event=(void *)(events.bytes+offset);
            CHECK(event->wd==watch);seen|=event->mask;offset+=sizeof(*event)+event->len;
        }
        CHECK(seen&(mode=='n'?IN_DELETE_SELF:IN_MODIFY));
    }
    CHECK(sc(__NR_close,fd,0,0,0)==0);
    if(denied) {
        static const char note[]="PASS: inotify host rejects symlink watch with EACCES\n";
        sc(__NR_write,1,(long)note,sizeof(note)-1,0);sc(__NR_exit_group,0,0,0,0);for(;;){}
    }
    static const char pass[]="PASS: inotify guest path semantics\n";
    sc(__NR_write,1,(long)pass,sizeof(pass)-1,0);sc(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
