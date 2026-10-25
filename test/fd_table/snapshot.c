/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "fd_handoff.h"

/* Production transport uses raw negative errno; host harness adapts libc.
 * Injection covers cleanup and partial transfers without changing the core. */
static long fail_number = -1, fail_errno, last_memfd = -1, chunk_limit;
long raw_syscall(long n,long a,long b,long c,long d,long e,long f)
{
    if(n==fail_number){fail_number=-1;return -fail_errno;}
    if(chunk_limit && (n==SYS_write || n==SYS_pread64) && c>chunk_limit)c=chunk_limit;
    long r=syscall(n,a,b,c,d,e,f);
    if(n==SYS_memfd_create && r>=0)last_memfd=r;
    return r==-1?-errno:r;
}

static void word(unsigned char *p, unsigned long long x)
{ for (int i = 0; i < 8; i++) p[i] = (unsigned char)(x >> (i * 8)); }
static void rejects(const unsigned char *data, size_t bytes, int error)
{
    struct fd_record slots[8], before[8];struct fd_table t;
    assert(fd_table_init(&t, slots, 8) == 0);
    memcpy(before, slots, sizeof(slots));
    assert(fd_snapshot_import(&t, data, bytes) == error);
    assert(!memcmp(slots, before, sizeof(slots)) && t.serial == 0);
}
static void format_checks(void)
{
    struct fd_record slots[8], outslots[8];struct fd_table t, out;
    assert(fd_table_init(&t, slots, 8) == 0);
    assert(fd_table_open(&t, 3, (struct fd_origin){7, FD_ACCESS_RO}, 0) == 0);
    assert(fd_table_dup(&t, 3, 4, 0) == 0);
    assert(fd_table_open(&t, 5, (struct fd_origin){9, FD_ACCESS_RW}, 1) == 0);
    assert(fd_table_dup(&t, 99, 6, 0) == 0);
    unsigned char storage[512], bad[512], *data = storage + 1;size_t bytes, written = 99;
    assert(fd_snapshot_size(&t, &bytes) == 0 && bytes == 32 + 3 * 48);
    memset(storage, 0x55, sizeof(storage));
    assert(fd_snapshot_export(&t, data, bytes - 1, &written) == -ENOSPC && written == 99);
    for (size_t i = 0; i < sizeof(storage); i++) assert(storage[i] == 0x55);
    assert(fd_snapshot_export(&t, data, bytes, &written) == 0 && written == bytes);
    assert(storage[0] == 0x55 && data[bytes] == 0x55);
    assert(!memcmp(data, "ELFFDS1\0", 8));
    assert(fd_table_init(&out, outslots, 8) == 0);
    assert(fd_snapshot_import(&out, data, bytes) == 0 && out.serial == t.serial);
    assert(!fd_table_get(&out, 5) && fd_table_get(&t, 5));
    assert(fd_table_get(&out, 3)->description == fd_table_get(&out, 4)->description);
    assert(fd_table_get(&out, 6)->origin.access == FD_ACCESS_UNKNOWN);
    assert(fd_snapshot_import(&out, data, bytes) == -EBUSY);
    assert(fd_table_open(&out, 5, (struct fd_origin){9, FD_ACCESS_RW}, 0) == 0);
    assert(fd_table_get(&out, 5)->generation > t.serial);
    for (size_t i = 0; i < bytes; i++) rejects(data, i, -EINVAL);
    rejects(data, bytes + 1, -EINVAL);
    const struct {size_t offset;unsigned long long value;} corruptions[] = {
        {0,0}, {8,2}, {16,0}, {24,0}, {24,~0ULL},
        {32,(unsigned long long)INT_MAX+1}, {40,1}, {48,0}, {48,99},
        {56,99}, {72,99}, {56,0}, /* known origin cannot have unknown identity */
        {80,3}, /* duplicate FD */
        {96,1}, /* duplicate assignment generation */
        {112,8}, {120,FD_ACCESS_RW}, /* same description, conflicting origin */
        {160,9}, /* unknown source must not carry a mount */
        {152,2}, /* description may not refer to a dup's generation */
    };
    for (size_t i=0;i<sizeof(corruptions)/sizeof(corruptions[0]);i++) {
        memcpy(bad,data,bytes);word(bad+corruptions[i].offset,corruptions[i].value);
        rejects(bad,bytes,-EINVAL);
    }
    struct fd_record one[1];struct fd_table small;
    assert(fd_table_init(&small,one,1)==0);
    assert(fd_snapshot_import(&small,data,bytes)==-ENOSPC && small.serial==0 && one[0].fd==-1);
    fd_table_range(&t,0,UINT_MAX,0);
    assert(fd_snapshot_export(&t,data,512-1,&written)==0 && written==32);
    assert(fd_table_init(&out,outslots,8)==0);
    assert(fd_snapshot_import(&out,data,written)==0 && out.serial==t.serial);
    puts("PASS: unaligned/versioned snapshot, CLOEXEC filtering, malformed input and atomic import");
}
static int receive(int argc,char **argv)
{
    assert(argc==7);
    int state=atoi(argv[2]),a=atoi(argv[3]),b=atoi(argv[4]),c=atoi(argv[5]),u=atoi(argv[6]);
    int seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
    assert(fcntl(state,F_GET_SEALS)==seals);
    unsigned char buffer[512];
    struct fd_record slots[8];struct fd_table t;assert(fd_table_init(&t,slots,8)==0);
    assert(fd_handoff_restore(&t,state,buffer,sizeof(buffer))==0);
    assert(!fd_table_get(&t,state)); /* transport is internal, not a guest record */
    assert(fd_table_get(&t,a)->origin.mount_id==17 && fd_table_get(&t,a)->origin.access==FD_ACCESS_RO);
    assert(fd_table_get(&t,b)->description==fd_table_get(&t,a)->description);
    assert(fd_table_get(&t,u)->origin.access==FD_ACCESS_UNKNOWN);
    assert(t.serial==4 && !fd_table_get(&t,c));
    assert(fcntl(c,F_GETFD)==-1 && errno==EBADF);
    assert(fcntl(a,F_GETFD)==0 && fcntl(b,F_GETFD)==0 && fcntl(u,F_GETFD)==0);
    assert(close(state)==0);
    assert(close(a)==0 && close(b)==0 && close(u)==0);
    return 0;
}
static void exec_checks(const char *self)
{
    struct fd_record slots[8], before[8];struct fd_table t;
    assert(fd_table_init(&t,slots,8)==0);
    int a=memfd_create("guest-fd",0);assert(a>=0);
    assert(fd_table_open(&t,a,(struct fd_origin){17,FD_ACCESS_RO},0)==0);
    int b=dup(a);assert(b>=0 && fd_table_dup(&t,a,b,0)==0);
    int c=fcntl(a,F_DUPFD_CLOEXEC,20);assert(c>=20 && fd_table_dup(&t,a,c,1)==0);
    int u=dup(a);assert(u>=0 && fd_table_dup(&t,999,u,0)==0);
    memcpy(before,slots,sizeof(slots));
    unsigned char buffer[512];size_t bytes;
    assert(fd_snapshot_export(&t,buffer,sizeof(buffer),&bytes)==0);
    fail_number=SYS_write;fail_errno=EIO;
    assert(fd_handoff_create(&t,buffer,sizeof(buffer))==-EIO);
    assert(fcntl((int)last_memfd,F_GETFD)==-1 && errno==EBADF);
    fail_number=SYS_fcntl;fail_errno=EPERM;
    assert(fd_handoff_create(&t,buffer,sizeof(buffer))==-EPERM);
    assert(fcntl((int)last_memfd,F_GETFD)==-1 && errno==EBADF);
    fail_number=SYS_write;fail_errno=EINTR;chunk_limit=7;
    int tmp=(int)fd_handoff_create(&t,buffer,sizeof(buffer));assert(tmp>=0);
    assert(fcntl(tmp,F_GETFD)==FD_CLOEXEC);
    struct fd_record restored_slots[8];struct fd_table restored;
    assert(fd_table_init(&restored,restored_slots,8)==0);
    assert(fd_handoff_restore(&restored,tmp,buffer,bytes-1)==-ENOSPC && restored.serial==0);
    fail_number=SYS_pread64;fail_errno=EIO;
    assert(fd_handoff_restore(&restored,tmp,buffer,bytes)==-EIO && restored.serial==0);
    fail_number=SYS_pread64;fail_errno=EINTR;
    assert(fd_handoff_restore(&restored,tmp,buffer,bytes)==0 && restored.serial==t.serial);
    chunk_limit=0;
    assert(fd_table_init(&restored,restored_slots,8)==0);
    assert(fd_handoff_restore(&restored,a,buffer,sizeof(buffer))==-EINVAL && restored.serial==0);
    assert(pwrite(tmp,"x",1,0)==-1 && errno==EPERM);
    /* Keep handoff FD out of the loader's low-number temporary FD range. */
    int state=fcntl(tmp,F_DUPFD,100);assert(state>=100 && close(tmp)==0);
    char nums[5][24];int fds[]={state,a,b,c,u};
    for(int i=0;i<5;i++)snprintf(nums[i],sizeof(nums[i]),"%d",fds[i]);
    char *args[]={(char*)self,"--receive",nums[0],nums[1],nums[2],nums[3],nums[4],NULL};
    /* Failed exec must not consume CLOEXEC records in the old table. */
    execv("/nonexistent-elf-fd-handoff-test",args);assert(errno==ENOENT);
    assert(!memcmp(before,slots,sizeof(slots)) && t.serial==4);
    assert(fcntl(c,F_GETFD)==FD_CLOEXEC);
    pid_t pid=fork();assert(pid>=0);
    if(!pid){execv(self,args);_exit(100);}
    int status;assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==0);
    assert(!memcmp(before,slots,sizeof(slots)) && fcntl(c,F_GETFD)==FD_CLOEXEC);
    assert(close(state)==0 && close(a)==0 && close(b)==0 && close(c)==0 && close(u)==0);
    puts("PASS: sealed memfd handoff across real exec, preserved provenance, failed-exec rollback and transport fault cleanup");
}
int main(int argc,char **argv)
{
    if(argc>1 && !strcmp(argv[1],"--receive"))return receive(argc,argv);
    format_checks();exec_checks(argv[0]);return 0;
}
