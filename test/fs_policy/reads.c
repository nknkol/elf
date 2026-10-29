/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
/* linux/inotify.h conflicts with libc fcntl.h definitions. */
#define IN_NONBLOCK O_NONBLOCK
#define IN_ALL_EVENTS 0xfff
static long call(long n,long a,long b,long c,long d,long e,long f)
{
    register long x0 __asm__("x0")=a,x1 __asm__("x1")=b,x2 __asm__("x2")=c,x3 __asm__("x3")=d;
    register long x4 __asm__("x4")=e,x5 __asm__("x5")=f,x8 __asm__("x8")=n;
    __asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory","cc");return x0;
}
#define C(n,a,b,c,d,e,f) call(__NR_##n,(long)(a),(long)(b),(long)(c),(long)(d),(long)(e),(long)(f))
#define CHECK(x) do { if(!(x)) { C(exit_group,__LINE__,0,0,0,0,0);for(;;){} } } while(0)
/* Inherited from the harness: host secret file, host hidden directory, pipe. */
#define SECRET_FD 10
#define HIDDEN_DIR_FD 11
#define PIPE_FD 12
static long open_at(long dir,const char *path,int flags) { return C(openat,dir,path,flags,0,0,0); }
static long open_file(const char *path,int flags) { return open_at(AT_FDCWD,path,flags); }
static void close_fd(long fd) { CHECK(C(close,fd,0,0,0,0,0)==0); }
static int same(const char *a,const char *b) { while(*a && *a==*b) { a++;b++; } return *a==*b; }
static void read_text(const char *path,const char *expected)
{
    char buffer[32];long fd=open_file(path,O_RDONLY);CHECK(fd>=0);
    long n=C(read,fd,buffer,sizeof(buffer)-1,0,0,0);CHECK(n>=0);buffer[n]=0;
    CHECK(same(buffer,expected));close_fd(fd);
}
/* Collect "|name|name|" from getdents64 with a deliberately chosen buffer size. */
static long list(long fd,unsigned size,char *out,long capacity)
{
    unsigned char buffer[1024];long used=0,count=0;out[used++]='|';
    for(;;) {
        long n=C(getdents64,fd,buffer,size,0,0,0);
        if(n<=0)return n<0?n:count;
        for(long offset=0;offset<n;) {
            unsigned short length=*(unsigned short *)(buffer+offset+16);
            const char *name=(const char *)buffer+offset+19;
            while(*name) { CHECK(used+2<capacity);out[used++]=*name++; }
            out[used++]='|';out[used]=0;count++;offset+=length;
        }
    }
}
static int listed(const char *names,const char *name)
{
    for(const char *p=names;*p;p++) {
        if(*p!='|')continue;
        const char *a=p+1,*b=name;
        while(*b && *a==*b) { a++;b++; }
        if(!*b && *a=='|')return 1;
    }
    return 0;
}
static int contains(const unsigned char *bytes,long size,const char *word)
{
    for(long i=0;i<size;i++) {
        long j=0;
        while(word[j] && i+j<size && bytes[i+j]==(unsigned char)word[j])j++;
        if(!word[j])return 1;
    }
    return 0;
}
/* The whole guest buffer, not just the returned prefix, must stay free of
 * hidden names: after normal batches, hidden-only batches and at EOF. */
static void no_residue(const char *path,unsigned size,const char *const *hidden)
{
    unsigned char buffer[1024];
    long fd=open_file(path,O_RDONLY|O_DIRECTORY);CHECK(fd>=0);
    for(;;) {
        for(unsigned i=0;i<sizeof(buffer);i++)buffer[i]=0xaa;
        long n=C(getdents64,fd,buffer,size,0,0,0);CHECK(n>=0);
        for(long i=0;hidden[i];i++)CHECK(!contains(buffer,sizeof(buffer),hidden[i]));
        for(long i=n;i<(long)sizeof(buffer);i++)CHECK(buffer[i]==0xaa);
        if(!n)break;
    }
    close_fd(fd);
}
static void watches(void)
{
    long notify=C(inotify_init1,IN_NONBLOCK,0,0,0,0,0);CHECK(notify>=0);
    /* A visible directory whose direct child is a hidden bind could name it. */
    CHECK(C(inotify_add_watch,notify,"/home/u/work",IN_ALL_EVENTS,0,0,0)==-EACCES);
    CHECK(C(inotify_add_watch,notify,"/home/u",IN_ALL_EVENTS,0,0,0)==-EACCES);
    CHECK(C(inotify_add_watch,notify,"/etc",IN_ALL_EVENTS,0,0,0)==-EACCES);
    CHECK(C(inotify_add_watch,notify,"/opt/ro",IN_ALL_EVENTS,0,0,0)>=0);
    CHECK(C(inotify_add_watch,notify,"/home/u/work/private/pub",IN_ALL_EVENTS,0,0,0)>=0);
    close_fd(notify);
}
static void expect_listing(const char *path,unsigned size,const char *const *names,long count)
{
    char out[512];long fd=open_file(path,O_RDONLY|O_DIRECTORY);CHECK(fd>=0);
    CHECK(list(fd,size,out,sizeof(out))==count+2);
    CHECK(listed(out,".") && listed(out,".."));
    for(long i=0;i<count;i++)CHECK(listed(out,names[i]));
    close_fd(fd);
}
static void hidden_paths(void)
{
    struct { char data[128]; } st;
    char buffer[64];
    /* Hidden names fail identically whether or not the object exists. */
    CHECK(open_file("/root-secret",O_RDONLY)==-EACCES);
    CHECK(open_file("/etc/passwd",O_RDONLY)==-EACCES);
    CHECK(open_file("/etc/missing",O_RDONLY)==-EACCES);
    CHECK(open_file("/missing/child",O_RDONLY)==-EACCES);
    CHECK(open_file("/root-secret",O_PATH)==-EACCES);
    CHECK(C(newfstatat,AT_FDCWD,"/etc",&st,0,0,0)==-EACCES);
    CHECK(C(newfstatat,AT_FDCWD,"/missing",&st,AT_SYMLINK_NOFOLLOW,0,0)==-EACCES);
    CHECK(C(statx,AT_FDCWD,"/root-secret",0,0x7ff,&st,0)==-EACCES);
    CHECK(C(faccessat,AT_FDCWD,"/root-secret",0,0,0,0)==-EACCES);
    CHECK(C(readlinkat,AT_FDCWD,"/link-visible",buffer,sizeof(buffer),0,0)==-EACCES);
    CHECK(C(getxattr,"/root-secret","user.test",buffer,sizeof(buffer),0,0)==-EACCES);
    CHECK(C(listxattr,"/root-secret",buffer,sizeof(buffer),0,0,0)==-EACCES);
    CHECK(C(statfs,"/etc",&st,0,0,0,0)==-EACCES);
    /* A hidden symlink cannot be used as a route even to a visible target. */
    CHECK(open_file("/link-visible",O_RDONLY)==-EACCES);
    /* A visible symlink cannot reach hidden content, nor can "..". */
    CHECK(open_file("/home/u/work/to-secret",O_RDONLY)==-EACCES);
    CHECK(open_file("/home/u/work/../sibling-secret",O_RDONLY)==-EACCES);
    CHECK(open_file("/home/u/work/private/x",O_RDONLY)==-EACCES);
    CHECK(open_file("/deny/file",O_RDONLY)==-EACCES);
    const char *args[]={"/root-secret",0};
    CHECK(C(execve,args[0],args,0,0,0,0)==-EACCES);
    int mount=0;
    CHECK(C(name_to_handle_at,AT_FDCWD,"/root-secret",buffer,&mount,0,0)==-ENOSYS);
}
static void traversal(void)
{
    struct { char data[128]; } st;
    char buffer[64];
    /* Ancestors of exposed binds: lookup, stat, directory open and cwd only. */
    CHECK(C(newfstatat,AT_FDCWD,"/",&st,0,0,0)==0);
    CHECK(C(newfstatat,AT_FDCWD,"/home/u",&st,0,0,0)==0);
    /* Trailing "." or "/" names the directory itself, not a hidden child. */
    CHECK(C(newfstatat,AT_FDCWD,"/.",&st,0,0,0)==0);
    CHECK(C(newfstatat,AT_FDCWD,"/home/",&st,0,0,0)==0);
    CHECK(C(newfstatat,AT_FDCWD,"/home/u/work/.",&st,0,0,0)==0);
    CHECK(C(newfstatat,AT_FDCWD,"/etc/.",&st,0,0,0)==-EACCES);
    CHECK(open_file("/home/u/work/./",O_RDONLY|O_DIRECTORY)>=0);
    CHECK(C(faccessat,AT_FDCWD,"/home",4,0,0,0)==0);
    CHECK(open_file("/",O_RDONLY)==-EACCES);
    CHECK(open_file("/home",O_RDWR|O_DIRECTORY)==-EACCES);
    CHECK(C(getxattr,"/home","user.test",buffer,sizeof(buffer),0,0)==-EACCES);
    long path=open_file("/home",O_PATH);CHECK(path>=0);
    CHECK(C(read,path,buffer,1,0,0,0)==-EACCES);close_fd(path);
    const char *home[]={"u"},*user[]={"work"},*root[]={"home","opt"};
    expect_listing("/",1024,root,2);
    /* Small buffers return one record at a time; hidden batches are skipped. */
    expect_listing("/",32,root,2);
    const char *in_root[]={"secret","etc","deny","link-visible","probe","host-",0};
    const char *in_user[]={"sibling",0},*in_work[]={"hidden",0};
    no_residue("/",1024,in_root);no_residue("/",32,in_root);
    no_residue("/home/u",40,in_user);no_residue("/home/u/work",1024,in_work);
    expect_listing("/home",1024,home,1);
    expect_listing("/home/u",40,user,1);
    const char *priv[]={"pub"};
    expect_listing("/home/u/work/private",1024,priv,1);
    const char *work[]={"file","to-secret","private","probe"};
    expect_listing("/home/u/work",1024,work,4);
    /* Relative lookups from an ancestor cwd keep the same decisions. */
    CHECK(C(chdir,"/etc",0,0,0,0,0)==-EACCES);
    CHECK(C(chdir,"/home",0,0,0,0,0)==0);
    long fd=open_file("u/work/file",O_RDONLY);CHECK(fd>=0);close_fd(fd);
    CHECK(open_file("u/sibling-secret",O_RDONLY)==-EACCES);
    CHECK(open_file("../root-secret",O_RDONLY)==-EACCES);
    long dir=open_file("/home/u",O_RDONLY|O_DIRECTORY);CHECK(dir>=0);
    CHECK(open_at(dir,"sibling-secret",O_RDONLY)==-EACCES);
    fd=open_at(dir,"work/file",O_RDONLY);CHECK(fd>=0);close_fd(fd);
    CHECK(C(fchdir,dir,0,0,0,0,0)==0);close_fd(dir);
    CHECK(C(getcwd,buffer,sizeof(buffer),0,0,0,0)==8 && same(buffer,"/home/u"));
    CHECK(C(chdir,"/",0,0,0,0,0)==0);
}
static void inherited(int stream)
{
    struct { char data[128]; } st;
    char buffer[16];struct iovec io={buffer,sizeof(buffer)};
    int pipefd[2];CHECK(C(pipe2,pipefd,0,0,0,0,0)==0);
    long sink=open_file("/home/u/work/sink",O_RDWR|O_CREAT|O_TRUNC);CHECK(sink>=0);
    /* fstat stays available; content reads of unknown files do not. */
    CHECK(C(fstat,SECRET_FD,&st,0,0,0,0)==0);
    CHECK(C(read,SECRET_FD,buffer,1,0,0,0)==-EACCES);
    CHECK(C(readv,SECRET_FD,&io,1,0,0,0)==-EACCES);
    CHECK(C(pread64,SECRET_FD,buffer,1,0,0,0)==-EACCES);
    CHECK(C(preadv,SECRET_FD,&io,1,0,0,0)==-EACCES);
    CHECK(C(preadv2,SECRET_FD,&io,1,0,0,0)==-EACCES);
    CHECK(C(mmap,0,4096,PROT_READ,MAP_PRIVATE,SECRET_FD,0)==-EACCES);
    CHECK(C(sendfile,pipefd[1],SECRET_FD,0,1,0,0)==-EACCES);
    CHECK(C(splice,SECRET_FD,0,pipefd[1],0,1,0)==-EACCES);
    CHECK(C(copy_file_range,SECRET_FD,0,sink,0,1,0)==-EACCES);
    CHECK(C(fgetxattr,SECRET_FD,"user.test",buffer,sizeof(buffer),0,0)==-EACCES);
    CHECK(C(flistxattr,SECRET_FD,buffer,sizeof(buffer),0,0,0)==-EACCES);
    CHECK(C(getdents64,HIDDEN_DIR_FD,buffer,sizeof(buffer),0,0,0)==-EACCES);
    CHECK(C(fchdir,HIDDEN_DIR_FD,0,0,0,0,0)==-EACCES);
    /* EBADF keeps priority over policy for invalid descriptors. */
    CHECK(C(read,99,buffer,1,0,0,0)==-EBADF);
    /* Inherited streams require the explicit option; local objects do not. */
    long expected=stream?3:-EACCES;
    CHECK(C(read,0,buffer,3,0,0,0)==expected);
    if(stream)CHECK(buffer[0]=='I' && buffer[1]=='N' && buffer[2]=='\n');
    CHECK(C(read,PIPE_FD,buffer,4,0,0,0)==(stream?4:-EACCES));
    if(!stream)CHECK(C(tee,PIPE_FD,pipefd[1],1,0,0,0)==-EACCES);
    close_fd(pipefd[0]);close_fd(pipefd[1]);
    int pair[2];CHECK(C(socketpair,AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,pair,0,0)==0);
    CHECK(C(read,pair[0],buffer,1,0,0,0)==-EAGAIN);
    close_fd(pair[0]);close_fd(pair[1]);
    long event=C(eventfd2,1,0,0,0,0,0);CHECK(event>=0);
    CHECK(C(read,event,buffer,8,0,0,0)==8);close_fd(event);
    close_fd(sink);
    CHECK(C(unlinkat,AT_FDCWD,"/home/u/work/sink",0,0,0,0)==0);
}
static void visible(void)
{
    char buffer[16];
    read_text("/home/u/work/file","work");
    read_text("/opt/ro/file","ro");
    read_text("/home/u/work/private/pub/file","pub");
    CHECK(open_file("/opt/ro/file",O_WRONLY)==-EROFS);
    long fd=open_file("/home/u/work/file",O_RDONLY);CHECK(fd>=0);
    long map=C(mmap,0,4096,PROT_READ,MAP_PRIVATE,fd,0);CHECK(map>0 || map<-4095);
    CHECK(((const char *)map)[0]=='w');CHECK(C(munmap,map,4096,0,0,0,0)==0);
    long dup=C(dup,fd,0,0,0,0,0);CHECK(dup>=0);
    CHECK(C(pread64,dup,buffer,4,0,0,0)==4);close_fd(dup);close_fd(fd);
    /* Visible symlink metadata, including O_PATH empty-name readlink. */
    long link=open_file("/home/u/work/to-secret",O_PATH|O_NOFOLLOW);CHECK(link>=0);
    CHECK(C(readlinkat,link,"",buffer,sizeof(buffer),0,0)==12);close_fd(link);
    int pipefd[2];CHECK(C(pipe2,pipefd,0,0,0,0,0)==0);
    long reader=C(dup,pipefd[0],0,0,0,0,0);CHECK(reader>=0);
    close_fd(pipefd[0]);close_fd(pipefd[1]);
    CHECK(C(read,reader,buffer,1,0,0,0)==0);close_fd(reader);
}
void run(long *stack)
{
    CHECK(stack[0]>=2);const char *mode=(const char *)stack[2];
    hidden_paths();
    if(mode[0]=='c') {
        /* After exec the policy and listing filter still apply. */
        const char *root[]={"home","opt"};
        expect_listing("/",1024,root,2);
        read_text("/home/u/work/file","work");
        /* exec carries no cwd tag; revalidation restores a known origin. */
        read_text("file","work");
        CHECK(open_file("../sibling-secret",O_RDONLY)==-EACCES);
        C(exit_group,0,0,0,0,0,0);for(;;){}
    }
    traversal();watches();visible();inherited(mode[0]=='s');
    CHECK(C(chdir,"/home/u/work",0,0,0,0,0)==0);
    const char *args[]={"/home/u/work/probe","child",0};
    C(execve,args[0],args,0,0,0,0);CHECK(0);
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl run\n");
