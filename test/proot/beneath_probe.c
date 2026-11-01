/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Layer image probe (test_union.py): opens the directory argv[1], then
 * argv[2] beneath it with openat2(O_PATH | O_NOFOLLOW, RESOLVE_BENEATH),
 * the lookup the kernel does itself. Prints "beneath=<0 or -errno>". */
#include <asm/unistd.h>
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static void out(const char *s){long n=0;while(s[n])n++;sc(__NR_write,1,(long)s,n,0,0,0);}
static void num(long v){char b[24];int i=23;b[i--]='\n';unsigned long u=v<0?-v:v;do{b[i--]='0'+u%10;u/=10;}while(u);if(v<0)b[i--]='-';sc(__NR_write,1,(long)(b+i+1),23-i,0,0,0);}
void run(long *sp)
{
    char **argv=(char **)(sp+1);
    /* O_PATH 010000000, O_DIRECTORY 040000, O_NOFOLLOW 0100000, O_CLOEXEC 02000000 (aarch64) */
    long dir=sc(__NR_openat,-100,(long)argv[1],010000000|040000|02000000,0,0,0);
    if(dir<0){out("beneath=dir ");num(dir);sc(__NR_exit_group,1,0,0,0,0,0);}
    unsigned long how[3]={010000000|0100000|02000000,0,8 /* RESOLVE_BENEATH */};
    long fd=sc(437 /* openat2 */,dir,(long)argv[2],(long)how,sizeof(how),0,0);
    out("beneath=");num(fd>=0?0:fd);
    sc(__NR_exit_group,0,0,0,0,0,0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
