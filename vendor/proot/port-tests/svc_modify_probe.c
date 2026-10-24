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
void run(long *sp) {
 char **av=(void*)(sp+1);if(sp[0]<3)goto done;
 char op=av[1][0];long fd=-100,ret=-22;char buf[256];
 struct {long sec,nsec;} times[2]={{1234567,0},{1234567,0}};
 if(op=='C'||op=='O'||op=='T'||op=='S'||op=='U')fd=sc(56,-100,(long)av[2],2,0,0,0);
 if(op=='c')ret=sc(53,-100,(long)av[2],0600,0,0,0);
 if(op=='C')ret=sc(52,fd,0600,0,0,0,0);
 if(op=='o'||op=='l')ret=sc(54,-100,(long)av[2],-1,-1,op=='l'?256:0,0);
 if(op=='O')ret=sc(55,fd,-1,-1,0,0,0);
 if(op=='u'||op=='n')ret=sc(88,-100,(long)av[2],(long)times,op=='n'?256:0,0,0);
 if(op=='U')ret=sc(88,fd,0,(long)times,0,0,0);
 if(op=='t')ret=sc(45,(long)av[2],2,0,0,0,0);
 if(op=='T')ret=sc(46,fd,2,0,0,0,0);
 if(op=='s')ret=sc(43,(long)av[2],(long)buf,0,0,0,0);
 if(op=='S')ret=sc(44,fd,(long)buf,0,0,0,0);
 if(op=='m')ret=sc(33,-100,(long)av[2],0010600,0,0,0);
 if(op=='b')ret=sc(52,-1,0600,0,0,0,0);
 if(op=='f')ret=sc(54,-100,(long)av[2],-1,-1,0x40000000,0);
 text("RET=");num(ret);
 done:sc(94,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
