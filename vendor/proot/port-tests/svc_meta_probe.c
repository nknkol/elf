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
#include <asm/stat.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
static void field(const char *label,long value){text(label);num(value);}
void run(long *sp)
{
    long argc=sp[0]; char **argv=(void*)(sp+1);
    if(argc<4){text("BAD_ARGS\n");goto done;}
    char op=argv[1][0]; const char *path=argv[2]; long value=parse(argv[3]);
    long ret, fd=-100;
    struct stat st;
    struct statx sx;
    char buf[256];
    for(int i=0;i<256;i++)buf[i]='Z';
    if(op=='s'||op=='e'||op=='i'){
        if(op=='e'||op=='i'){
            fd=sc(56,-100,(long)path,O_PATH|O_NOFOLLOW,0,0,0);
            if(fd<0){field("FD=",fd);goto done;}
            path="";value|=AT_EMPTY_PATH;
        }
        ret=op=='i'?sc(80,fd,(long)&st,0,0,0,0):sc(79,fd,(long)path,(long)&st,value,0,0);
        field("RET=",ret);
        if(ret==0){field("TYPE=",st.st_mode&0170000);field("SIZE=",st.st_size);}
    }else if(op=='t'||op=='x'){
        if(op=='x'){
            fd=sc(56,-100,(long)path,O_PATH|O_NOFOLLOW,0,0,0);
            if(fd<0){field("FD=",fd);goto done;}
            path="";value|=AT_EMPTY_PATH;
        }
        ret=sc(291,fd,(long)path,value,STATX_BASIC_STATS,(long)&sx,0);
        field("RET=",ret);
        if(ret==0){field("TYPE=",sx.stx_mode&0170000);field("SIZE=",sx.stx_size);}
    }else if(op=='r'||op=='q'){
        if(value>255)goto done;
        if(op=='q'){
            fd=sc(56,-100,(long)path,O_PATH|O_NOFOLLOW,0,0,0);
            if(fd<0){field("FD=",fd);goto done;}
            path="";
        }
        ret=sc(78,fd,(long)path,(long)buf,value,0,0);
        field("RET=",ret);
        if(ret>=0&&ret<256){text("LINK=");sc(64,1,(long)buf,ret,0,0,0);text("\n");field("AFTER=",buf[ret]);}
    }else if(op=='c'||op=='f'||op=='g'){
        if(value>255)goto done;
        ret=0;
        if(op=='c')ret=sc(49,(long)path,0,0,0,0,0);
        if(op=='f'){
            fd=sc(56,-100,(long)path,O_RDONLY,0,0,0);
            if(fd<0){field("FD=",fd);goto done;}
            ret=sc(50,fd,0,0,0,0,0);
        }
        field("CHDIR=",ret);
        ret=sc(17,(long)buf,value,0,0,0,0);
        field("RET=",ret);
        if(ret>0&&ret<256){text("CWD=");text(buf);text("\n");field("TERMINATOR=",buf[ret-1]);}
        long file=sc(56,-100,(long)"file",O_RDONLY,0,0,0);
        field("OPEN=",file<0?file:0);
        if(file>=0){long n=sc(63,file,(long)buf,256,0,0,0);if(n>0){text("DATA=");sc(64,1,(long)buf,n,0,0,0);}sc(57,file,0,0,0,0,0);}
    }else if(op=='a'||op=='b'){
        ret=op=='a'?sc(48,-100,(long)path,value,0,0,0):sc(439,-100,(long)path,0,value,0,0);
        field("RET=",ret);
    }
    if(fd>=0)sc(57,fd,0,0,0,0,0);
 done: sc(94,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
