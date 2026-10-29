/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Native-vs-loader micro benchmarks: raw syscalls, no libc. Prints one
 * "name ns_per_op" line per case. argv: work directory (guest path). */
#include <asm/unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
static long call(long n,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define C(n,a,b,c,d,e,f) call(__NR_##n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define CHECK(x) do { if(!(x)) { C(exit_group,__LINE__,0,0,0,0,0);for(;;){} } } while(0)
static long now(void) { struct timespec t;C(clock_gettime,CLOCK_MONOTONIC,&t,0,0,0,0);return t.tv_sec*1000000000L+t.tv_nsec; }
static void print(const char *name,long total,long count)
{
    char line[96];long n=0,value=total/count;
    while(*name)line[n++]=*name++;
    line[n++]=' ';
    char digits[24];int d=0;do { digits[d++]='0'+value%10;value/=10; } while(value);
    while(d)line[n++]=digits[--d];
    line[n++]='\n';C(write,1,line,n,0,0,0);
}
static char path[256],file[256];
static void join(char *out,const char *a,const char *b)
{ while(*a)*out++=*a++; *out++='/'; while(*b)*out++=*b++; *out=0; }
void run(long *stack)
{
    CHECK(stack[0]>=2);
    const char *dir=(const char *)stack[2];
    join(path,dir,"bench");
    join(file,path,"file");
    char buffer[4096],name[16];
    for(int i=0;i<4096;i++)buffer[i]=(char)i;
    long fd=C(openat,AT_FDCWD,file,O_RDWR,0,0,0);CHECK(fd>=0);
    struct { char data[128]; } st;
    long t,n;
#define BENCH(label,count,...) do { t=now(); for(n=0;n<(count);n++) { __VA_ARGS__; } print(label,now()-t,count); } while(0)
    BENCH("getpid",50000,C(getpid,0,0,0,0,0,0));
    BENCH("fstat",50000,CHECK(C(fstat,fd,&st,0,0,0,0)==0));
    BENCH("stat",20000,CHECK(C(newfstatat,AT_FDCWD,file,&st,0,0,0)==0));
    BENCH("open_close",10000,{ long f=C(openat,AT_FDCWD,file,O_RDONLY,0,0,0);CHECK(f>=0);C(close,f,0,0,0,0,0); });
    BENCH("pread_4k",50000,CHECK(C(pread64,fd,buffer,4096,0,0,0)==4096));
    BENCH("pwrite_4k",20000,CHECK(C(pwrite64,fd,buffer,4096,0,0,0)==4096));
    BENCH("readdir_64",2000,{
        long d=C(openat,AT_FDCWD,path,O_RDONLY|O_DIRECTORY,0,0,0);CHECK(d>=0);
        long total=0,got;
        while((got=C(getdents64,d,buffer,sizeof(buffer),0,0,0))>0)total+=got;
        CHECK(got==0 && total>0);C(close,d,0,0,0,0,0); });
    BENCH("mmap_64k",20000,{
        long m=C(mmap,0,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        CHECK(m>0 || m<-4095);C(munmap,m,65536,0,0,0,0); });
    (void)name;
    C(exit_group,0,0,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
