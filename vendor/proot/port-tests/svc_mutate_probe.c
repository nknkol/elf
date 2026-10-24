/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Freestanding guest. All file operations use ordinary SVC instructions. */
__attribute__((noinline)) static long sc(long n,long a,long b,long c,long d,long e,long f)
{
    register long x8 __asm__("x8")=n;
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c;
    register long x3 __asm__("x3")=d,x4 __asm__("x4")=e,x5 __asm__("x5")=f;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
    return x0;
}
static void text(const char *s){long n=0;while(s[n])n++;sc(64,1,(long)s,n,0,0,0);}
static void num(long x){char b[32];int i=31;b[i--]='\n';unsigned long v=x<0?-x:x;do{b[i--]='0'+v%10;v/=10;}while(v);if(x<0)b[i--]='-';sc(64,1,(long)(b+i+1),31-i,0,0,0);}
static long parse(const char *s){long x=0;while(*s>='0'&&*s<='9')x=x*10+*s++-'0';return x;}
#include <linux/fcntl.h>
void run(long *sp)
{
    long argc=sp[0];char **argv=(void*)(sp+1);
    if(argc<5){text("BAD_ARGS\n");goto done;}
    long oldfd=AT_FDCWD,newfd=AT_FDCWD,ret=-38;
    if(argc>=6 && argv[5][0]!='-'){
        oldfd=sc(56,AT_FDCWD,(long)argv[5],O_RDONLY|O_DIRECTORY,0,0,0);
        if(oldfd<0){text("DIR_ERROR=");num(oldfd);goto done;}
    }
    if(argc>=7 && argv[6][0]!='-'){
        newfd=sc(56,AT_FDCWD,(long)argv[6],O_RDONLY|O_DIRECTORY,0,0,0);
        if(newfd<0){text("DIR_ERROR=");num(newfd);goto done;}
    }
    char op=argv[1][0];long value=parse(argv[4]);
    if(op=='m')ret=sc(34,oldfd,(long)argv[2],value,0,0,0);
    if(op=='u')ret=sc(35,oldfd,(long)argv[2],value,0,0,0);
    if(op=='s')ret=sc(36,(long)argv[2],oldfd,(long)argv[3],0,0,0);
    if(op=='r')ret=sc(38,oldfd,(long)argv[2],newfd,(long)argv[3],0,0);
    if(op=='R')ret=sc(276,oldfd,(long)argv[2],newfd,(long)argv[3],value,0);
    if(op=='l')ret=sc(37,oldfd,(long)argv[2],newfd,(long)argv[3],value,0);
    text("RET=");num(ret);
    if(oldfd>=0)sc(57,oldfd,0,0,0,0,0);
    if(newfd>=0)sc(57,newfd,0,0,0,0,0);
 done:sc(94,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
