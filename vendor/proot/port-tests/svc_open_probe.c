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
void run(long *sp)
{
    long argc=sp[0];char **argv=(void*)(sp+1);long dirfd=-100;
    if(argc<3){text("BAD_ARGS\n");goto done;}
    if(argc>=4){
        dirfd=sc(56,-100,(long)argv[3],0,0,0,0);
        if(dirfd<0){text("DIR_ERROR=");num(dirfd);goto done;}
        if(argc>=5){
            if(sc(50,dirfd,0,0,0,0,0)<0){text("CHDIR_ERROR\n");goto done;}
            text("READY\n");
            char signal;
            if(sc(63,0,(long)&signal,1,0,0,0)!=1){text("SYNC_ERROR\n");goto done;}
            char cwd[256];long r=sc(17,(long)cwd,sizeof(cwd),0,0,0,0);
            text("CWD_RET=");num(r<0?r:0);
            text("FCHDIR_RET=");num(sc(50,dirfd,0,0,0,0,0));
            r=sc(56,-100,(long)argv[1],0,0,0,0);
            text("CWD_OPEN=");num(r<0?r:0);
            if(r>=0)sc(57,r,0,0,0,0,0);
        }
    }
    long fd=sc(56,dirfd,(long)argv[1],parse(argv[2]),0600,0,0);
    text("OPEN=");num(fd<0?fd:0);
    if(fd>=0){char data[64];long n=sc(63,fd,(long)data,sizeof(data),0,0,0);text("READ=");num(n);if(n>0){text("DATA=");sc(64,1,(long)data,n,0,0,0);}sc(57,fd,0,0,0,0,0);}
    if(dirfd>=0)sc(57,dirfd,0,0,0,0,0);
 done:sc(94,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
