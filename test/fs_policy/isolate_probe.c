/* SPDX-License-Identifier: GPL-2.0-or-later */
/* --isolate probe. Mode f: a kernel call issued from the payload's own
 * `svc; ret` (as if the guest jumped past the payload logic) opens argv[2],
 * a host path. Prints "direct=<fd or -errno>"; the guest filter must refuse
 * it. Mode s: a UNIX stream socket bound at argv[2], a client connected to
 * it, one message across, and a datagram socketpair; prints "socket=ok" or
 * the failing step and its result. */
#include <asm/unistd.h>
#include "elf_abi.h"
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static long via(unsigned long gadget,long n,long a,long b,long c)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register unsigned long x16 __asm__("x16")=gadget;
    __asm__ volatile("blr x16":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x16):"memory","cc","x30");
    return x0;
}
static void out(const char *s){long n=0;while(s[n])n++;sc(__NR_write,1,(long)s,n,0,0,0);}
static void num(long v){char b[24];int i=23;b[i--]='\n';unsigned long u=v<0?-v:v;do{b[i--]='0'+u%10;u/=10;}while(u);if(v<0)b[i--]='-';sc(__NR_write,1,(long)(b+i+1),23-i,0,0,0);}
static long fail(const char *step,long rc){out("socket=");out(step);out(" ");num(rc);sc(__NR_exit_group,1,0,0,0,0,0);return rc;}
static void sockets(const char *path)
{
    struct { unsigned short family; char path[108]; } address={1,{0}};
    long n=0;while(path[n] && n<107){address.path[n]=path[n];n++;}
    long length=2+n+1;
    long server=sc(__NR_socket,1,1,0,0,0,0);
    if(server<0)fail("socket",server);
    long rc=sc(__NR_bind,server,(long)&address,length,0,0,0);
    if(rc<0)fail("bind",rc);
    rc=sc(__NR_listen,server,1,0,0,0,0);
    if(rc<0)fail("listen",rc);
    long client=sc(__NR_socket,1,1,0,0,0,0);
    rc=client<0?client:sc(__NR_connect,client,(long)&address,length,0,0,0);
    if(rc<0)fail("connect",rc);
    long peer=sc(__NR_accept,server,0,0,0,0,0);
    if(peer<0)fail("accept",peer);
    char buf[8];
    if(sc(__NR_write,client,(long)"ping",4,0,0,0)!=4 || sc(__NR_read,peer,(long)buf,8,0,0,0)!=4)
        fail("transfer",-1);
    int pair[2];
    rc=sc(__NR_socketpair,1,2 /* SOCK_DGRAM */,0,(long)pair,0,0);
    if(rc<0)fail("socketpair",rc);
    if(sc(__NR_write,pair[0],(long)"ab",2,0,0,0)!=2 || sc(__NR_write,pair[0],(long)"c",1,0,0,0)!=1 ||
       sc(__NR_read,pair[1],(long)buf,8,0,0,0)!=2)
        fail("datagrams",-1);
    sc(__NR_unlinkat,-100,(long)path,0,0,0,0);
    out("socket=ok\n");
    sc(__NR_exit_group,0,0,0,0,0,0);
}
void run(long *sp)
{
    char **argv=(char **)(sp+1);
    const char *path=argv[2];
    if(argv[1][0]=='s')sockets(path);
    unsigned long gadget=0;
    for(unsigned *p=(unsigned *)PAYLOAD_FIXED_BASE;p<(unsigned *)(PAYLOAD_FIXED_BASE+0x100000);p++)
        if(p[0]==0xd4000001 && p[1]==0xd65f03c0){gadget=(unsigned long)p;break;}
    if(!gadget){out("gadget=missing\n");sc(__NR_exit_group,1,0,0,0,0,0);}
    long fd=via(gadget,__NR_openat,-100,(long)path,0);
    out("direct=");num(fd>=0?0:fd);
    fd=sc(__NR_openat,-100,(long)path,0,0,0,0);
    out("hooked=");num(fd>=0?0:fd);
    sc(__NR_exit_group,0,0,0,0,0,0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
