/* SPDX-License-Identifier: GPL-2.0-or-later */
/* --seccomp-backstop probe. Mode m: write a raw `svc` into code that is
 * already executable (through /proc/self/mem, so no hook ever sees it) and
 * open /etc/alpine-release with it. Mode x: ask for an RWX mapping. Mode w:
 * a hooked svc whose x8 has high bits set above openat. */
#include <asm/unistd.h>
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static void out(const char *s,long n){if(n<0){n=0;while(s[n])n++;}sc(__NR_write,1,(long)s,n,0,0,0);}
static void num(long v){char b[24];int i=23;b[i--]='\n';unsigned long u=v<0?-v:v;do{b[i--]='0'+u%10;u/=10;}while(u);if(v<0)b[i--]='-';out(b+i+1,23-i);}
void run(long *sp)
{
    char mode=((char **)(sp+1))[1][0];
    if(mode=='x') {
        long r=sc(__NR_mmap,0,4096,7,0x22,-1,0);
        out("rwx=",-1);num(r<0 && r>-4096?r:0);
        sc(__NR_exit_group,0,0,0,0,0,0);
    }
    if(mode=='w') {
        /* The kernel uses the low 32 bits of x8 as the number: high bits
         * must not route a known call past the payload. */
        long fd=sc(0x100000000l|__NR_openat,-100,(long)"/etc/alpine-release",0,0,0,0);
        char buf[64];long n=fd>=0?sc(__NR_read,fd,(long)buf,sizeof(buf),0,0,0):0;
        out("open=",-1);
        if(fd<0)num(fd);else out(buf,n);
        sc(__NR_exit_group,0,0,0,0,0,0);
    }
    unsigned *page=(unsigned *)sc(__NR_mmap,0,4096,3,0x22,-1,0);
    page[0]=0xd2800000|(__NR_openat<<5)|8; /* mov x8, #openat */
    page[1]=0xd503201f;                    /* nop: svc written below */
    page[2]=0xd65f03c0;                    /* ret */
    sc(__NR_mprotect,(long)page,4096,5,0,0,0);
    long m=sc(__NR_openat,-100,(long)"/proc/self/mem",2,0,0,0);
    unsigned svc=0xd4000001;
    if(m<0 || sc(__NR_pwrite64,m,(long)&svc,4,(long)(page+1),0,0)!=4) {
        out("mem=failed\n",-1);sc(__NR_exit_group,1,0,0,0,0,0);
    }
    __asm__ volatile("dc cvau, %0\n dsb ish\n ic ivau, %0\n dsb ish\n isb"::"r"(page):"memory");
    long fd=((long(*)(long,const char *,long,long))page)(-100,"/etc/alpine-release",0,0);
    char buf[64];long n=fd>=0?sc(__NR_read,fd,(long)buf,sizeof(buf),0,0,0):0;
    out("open=",-1);
    if(fd<0)num(fd);else out(buf,n);
    sc(__NR_exit_group,0,0,0,0,0,0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
