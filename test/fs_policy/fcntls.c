/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <fcntl.h>
#include <errno.h>
#define QUERY 0x46445452
#define HIGH (1ul<<32)
static long call(long n,long a,long b,long c,long d)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=0,x5 __asm__("x5")=0,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define CHECK(x) do { if(!(x)) { call(__NR_exit_group,__LINE__,0,0,0);for(;;){} } } while(0)
static long ctl(long fd,long cmd,long arg) {return call(__NR_fcntl,fd,cmd,arg,0);}
static long query(long selector,long fd) {return call(__NR_prctl,QUERY,selector,fd,0);}
static void denied(long fd,long error)
{
    CHECK(ctl(fd,F_SET_RW_HINT,0)==error);
    CHECK(ctl(fd,F_SET_FILE_RW_HINT,0)==error);
}
static void no_locks(long fd)
{
    int commands[]={F_GETLK,F_SETLK,F_SETLKW,F_OFD_GETLK,F_OFD_SETLK,F_OFD_SETLKW};
    for(unsigned i=0;i<sizeof(commands)/sizeof(commands[0]);i++)
        CHECK(ctl(fd,commands[i]|HIGH,0)==-EACCES);
}
void run(long *stack)
{
    const char *mode=(const char *)stack[2];int native=mode[0]=='n';
    const char *path=native?(const char *)stack[3]:"/rw/file";
    long fd=call(__NR_openat,AT_FDCWD,(long)path,O_RDWR,0);CHECK(fd>=0);
    long du=ctl(fd,F_DUPFD|HIGH,0);CHECK(du>=0 && du!=fd);
    long clo=ctl(fd,F_DUPFD_CLOEXEC|HIGH,0);CHECK(clo>=0 && clo!=du);
    CHECK(ctl(clo,F_GETFD,0)==FD_CLOEXEC);
    CHECK(ctl(du,F_SETFD|HIGH,FD_CLOEXEC)==0);
    CHECK(ctl(du,F_GETFD,0)==FD_CLOEXEC);
    if(!native) {
        CHECK(query(2,du)==query(2,fd) && query(2,clo)==query(2,fd));
        CHECK(query(4,du)==query(4,fd) && query(5,du)==query(5,fd));
        CHECK(query(3,du)==1 && query(3,clo)==1);
    }
    CHECK(ctl(du,F_SETFD|HIGH,0)==0);
    if(!native)CHECK(query(3,du)==0);
    CHECK(ctl(du,F_SETFL|HIGH,O_APPEND|O_NONBLOCK)==0);
    CHECK((ctl(fd,F_GETFL,0)&(O_APPEND|O_NONBLOCK))==(O_APPEND|O_NONBLOCK));
    CHECK(ctl(fd,F_SETFL,0)==0);
#ifdef GUARDED
    long ro=call(__NR_openat,AT_FDCWD,(long)"/ro/file",O_RDONLY,0);CHECK(ro>=0);
    long deny=call(__NR_openat,AT_FDCWD,(long)"/deny/file",O_RDONLY,0);CHECK(deny>=0);
    denied(ro,-EROFS);denied(deny,-EACCES);no_locks(deny);
    int pipes[2];CHECK(call(__NR_pipe2,(long)pipes,0,0,0)==0);
    denied(pipes[1],-EACCES);no_locks(pipes[0]);
    long pipe_size=ctl(pipes[1],F_GETPIPE_SZ,0);CHECK(pipe_size>0);
    CHECK(ctl(pipes[1],F_SETPIPE_SZ,pipe_size)==pipe_size);
    CHECK(ctl(pipes[1],F_GETPIPE_SZ,0)==pipe_size);
    long old_flags=ctl(fd,F_GETFL,0);
    CHECK(ctl(fd,F_SETFL|HIGH,O_ASYNC)==-EOPNOTSUPP);
    CHECK(ctl(fd,F_GETFL,0)==old_flags);
    int unsupported[]={F_SETLEASE,F_NOTIFY,F_SETOWN,F_SETOWN_EX,F_SETSIG,
                       F_ADD_SEALS,F_CANCELLK,0x7fffffff};
    for(unsigned i=0;i<sizeof(unsupported)/sizeof(unsupported[0]);i++)
        CHECK(ctl(fd,unsupported[i]|HIGH,0)==-EOPNOTSUPP);
    long mem=call(__NR_memfd_create,(long)"seal-policy",2,0,0);CHECK(mem>=0);
    CHECK(ctl(mem,F_GET_SEALS,0)==0);
    CHECK(ctl(mem,F_ADD_SEALS|HIGH,F_SEAL_WRITE)==-EOPNOTSUPP);
    CHECK(ctl(mem,F_GET_SEALS,0)==0);
    struct flock readlock={.l_type=F_RDLCK,.l_whence=0,.l_start=0,.l_len=1};
    CHECK(ctl(ro,F_SETLK,(long)&readlock)==0);
    readlock.l_type=F_UNLCK;CHECK(ctl(ro,F_SETLK,(long)&readlock)==0);
    CHECK(ctl(ro,F_SETFL,O_RDWR)==0);
    CHECK((ctl(ro,F_GETFL,0)&O_ACCMODE)==O_RDONLY);
    CHECK(call(__NR_write,ro,(long)"x",1,0)==-EROFS);
#endif
    long results[10];
    struct flock lock={.l_type=F_WRLCK,.l_whence=0,.l_start=0,.l_len=1};
    results[0]=ctl(fd,F_GETLK,(long)&lock);
    lock.l_type=F_WRLCK;results[1]=ctl(fd,F_SETLK,(long)&lock);
    lock.l_type=F_UNLCK;results[2]=ctl(fd,F_SETLKW,(long)&lock);
    lock.l_type=F_WRLCK;lock.l_pid=0;results[3]=ctl(fd,F_OFD_GETLK,(long)&lock);
    lock.l_type=F_WRLCK;lock.l_pid=0;results[4]=ctl(fd,F_OFD_SETLK,(long)&lock);
    lock.l_type=F_UNLCK;lock.l_pid=0;results[5]=ctl(fd,F_OFD_SETLKW,(long)&lock);
    results[6]=ctl(fd,F_SET_RW_HINT,0);
    results[7]=ctl(fd,F_SET_FILE_RW_HINT,0);
    results[8]=ctl(-1,F_GETFD,0);
    results[9]=ctl(fd,F_GET_SEALS,0);
    CHECK(call(__NR_write,1,(long)results,sizeof(results),0)==sizeof(results));
    call(__NR_exit_group,0,0,0,0);for(;;){}
}
__asm__(".global _start\n_start:\n mov x0,sp\n bl run\n");
