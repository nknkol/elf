/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
static long call(long n,long a,long b,long c,long d,long e)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0,0);for(;;){} } } while(0)
static const char name[]="user.elf_xattr", value[]="guest";
static long set(long n,const char *p,long flags)
{ return call(n,(long)p,(long)name,(long)value,5,flags); }
static long remove_attr(long n,const char *p)
{ return call(n,(long)p,(long)name,0,0,0); }
static void read_attr(const char *p)
{
    char buf[128];
    CHECK(call(__NR_getxattr,(long)p,(long)name,0,0,0)==4);
    CHECK(call(__NR_getxattr,(long)p,(long)name,(long)buf,3,0)==-ERANGE);
    CHECK(call(__NR_getxattr,(long)p,(long)name,(long)buf,sizeof(buf),0)==4);
    CHECK(buf[0]=='s' && buf[1]=='e' && buf[2]=='e' && buf[3]=='d');
    CHECK(call(__NR_lgetxattr,(long)p,(long)name,(long)buf,sizeof(buf),0)==4);
    CHECK(call(__NR_listxattr,(long)p,0,0,0,0)>0);
    CHECK(call(__NR_listxattr,(long)p,(long)buf,sizeof(buf),0,0)>0);
    CHECK(call(__NR_llistxattr,(long)p,(long)buf,sizeof(buf),0,0)>0);
}
static void denied(const char *p,long error)
{
    CHECK(set(__NR_setxattr,p,0)==error);
    CHECK(set(__NR_lsetxattr,p,0)==error);
    CHECK(remove_attr(__NR_removexattr,p)==error);
    CHECK(remove_attr(__NR_lremovexattr,p)==error);
}
void run(void)
{
    read_attr("/ro/file");read_attr("/rw/file");
    CHECK(set(__NR_setxattr,0,0)==-EFAULT);
    CHECK(set(__NR_setxattr,"",0)==-ENOENT);
#ifdef GUARDED
    denied("/ro/file",-EROFS);denied("/deny/file",-EACCES);
    denied("rw/file",-EACCES); /* Initial cwd is not a trusted source. */
    CHECK(set(__NR_setxattr,"/rw/to_ro",0)==-EROFS);
    CHECK(remove_attr(__NR_removexattr,"/rw/to_ro")==-EROFS);
    /* l* must check the symlink view, not its writable target. */
    CHECK(set(__NR_lsetxattr,"/ro/to_rw",0)==-EROFS);
    CHECK(remove_attr(__NR_lremovexattr,"/ro/to_rw")==-EROFS);
#else
    CHECK(set(__NR_setxattr,"/ro/file",0)==0);
    CHECK(remove_attr(__NR_removexattr,"/ro/file")==0);
#endif
    /* A followed link in ro may name a writable target. */
    CHECK(set(__NR_setxattr,"/ro/to_rw",2)==0);
    CHECK(set(__NR_setxattr,"/rw/file",1)==-EEXIST);
    CHECK(remove_attr(__NR_removexattr,"/ro/to_rw")==0);
    CHECK(remove_attr(__NR_removexattr,"/rw/file")==-ENODATA);
    CHECK(set(__NR_lsetxattr,"/rw/file",1)==0);
    CHECK(remove_attr(__NR_lremovexattr,"/rw/file")==0);
    CHECK(set(__NR_setxattr,"/ro/nested/file",0)==0);
    CHECK(call(__NR_chdir,(long)"/rw",0,0,0,0)==0);
    CHECK(set(__NR_setxattr,"file",0)==0);
    CHECK(set(__NR_setxattr,"/rw/missing",0)==-ENOENT);
    CHECK(call(__NR_getxattr,(long)"/rw/to_ro",(long)"user.absent",0,0,0)==-ENODATA);
    /* No-follow on a dangling link must reach the link, not return ENOENT. */
    CHECK(call(__NR_lgetxattr,(long)"/rw/dangling",(long)name,0,0,0)==-ENODATA);
    CHECK(call(__NR_getxattr,(long)"/rw/dangling",(long)name,0,0,0)==-ENOENT);
    call(__NR_exit_group,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\n bl run\n");
