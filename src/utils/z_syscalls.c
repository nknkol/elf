#include <syscall.h>
#include <fcntl.h>
#include <errno.h>

#include "z_asm.h"
#include "z_syscalls.h"

static int z_errno_storage;

int *z_perrno(void)
{
	return &z_errno_storage;
}

static long check_error(long rc)
{
	if (rc < 0 && rc > -4096) {
		z_errno = -rc;
		rc = -1;
	}
	return rc;
}

#define SYSCALL(name, ...)  check_error(z_syscall(SYS_##name, __VA_ARGS__))
#define DEF_SYSCALL1(ret, name, t1, a1) \
ret z_##name(t1 a1) \
{ \
	return (ret)SYSCALL(name, a1); \
}
#define DEF_SYSCALL2(ret, name, t1, a1, t2, a2) \
ret z_##name(t1 a1, t2 a2) \
{ \
	return (ret)SYSCALL(name, a1, a2); \
}
#define DEF_SYSCALL3(ret, name, t1, a1, t2, a2, t3, a3) \
ret z_##name(t1 a1, t2 a2, t3 a3) \
{ \
	return (ret)SYSCALL(name, a1, a2, a3); \
}

DEF_SYSCALL3(int, openat, int, dirfd, const char *, filename, int, flags)
DEF_SYSCALL3(ssize_t, read, int, fd, void *, buf, size_t, count)
DEF_SYSCALL3(ssize_t, write, int, fd, const void *, buf, size_t, count)
DEF_SYSCALL1(int, close, int, fd)
DEF_SYSCALL3(int, lseek, int, fd, off_t, off, int, whence)
DEF_SYSCALL2(int, ftruncate, int, fd, off_t, length)
DEF_SYSCALL1(int, exit, int, status)
DEF_SYSCALL1(int, chdir, const char *, path)
DEF_SYSCALL2(int, munmap, void *, addr, size_t, length)
DEF_SYSCALL3(int, mprotect, void *, addr, size_t, length, int, prot)
DEF_SYSCALL3(int, prctl, int, option, unsigned long, arg2, unsigned long, arg3)
DEF_SYSCALL2(char *, getcwd, char *, buf, size_t, size)

int z_open(const char * filename, int flags)
{
	return z_openat(AT_FDCWD, filename, flags);
}

void *
z_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	/* i386 has map (old_mmap) and mmap2, old_map is a legacy single arg
	 * function, use mmap2 but it needs offset in page units.
	 * In same time mmap2 does not exist on x86-64.
	 */
#ifdef SYS_mmap2
	return (void *)SYSCALL(mmap2, addr, length, prot, flags, fd, offset >> 12);
#else
	return (void *)SYSCALL(mmap, addr, length, prot, flags, fd, offset);
#endif
}

int z_memfd_create(const char *name, unsigned int flags)
{
#ifdef SYS_memfd_create
	return (int)SYSCALL(memfd_create, name, flags);
#else
	(void)name; (void)flags;
	z_errno = ENOSYS;
	return -1;
#endif
}

ssize_t z_readlink(const char *path, char *buf, size_t bufsiz)
{
#if defined(SYS_readlinkat)
	/* Prefer readlinkat: works for相对/绝对路径且更通用 */
	return (ssize_t)SYSCALL(readlinkat, AT_FDCWD, path, buf, bufsiz);
#elif defined(SYS_readlink)
	return (ssize_t)SYSCALL(readlink, path, buf, bufsiz);
#else
	return -1;
#endif
}
