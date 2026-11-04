/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Signal-driven I/O settings HarmonyOS refuses (async_io.h). */
#include <asm/unistd.h>
#include <errno.h>
#include <stdint.h>
#include "async_io.h"

extern long raw_syscall(long, long, long, long, long, long, long);

#define FIOASYNC_ 0x5452
#define O_ASYNC_ 020000
#define F_GETFL_ 3
#define F_SETFL_ 4
#define F_SETOWN_ 8
#define F_GETOWN_ 9
#define F_SETSIG_ 10
#define F_GETSIG_ 11
#define F_SETOWN_EX_ 15
#define F_GETOWN_EX_ 16
#define SLOTS 64

/* Per FD number of this process: kept only for settings the kernel refused
 * (otherwise the kernel's own state answers). fork copies it; an exec
 * starts without (the kernel's flags survive, these do not). */
static struct async_fd {
    int fd;            /* -1: free */
    uint64_t dev, ino; /* the object then: a reused number is another */
    int async;         /* O_ASYNC / FIOASYNC as set */
    int owner_set, sig_set;
    struct { int type, pid; } owner;
    int sig;
} slots[SLOTS];
static int initialized, lock_word;

static void lock(void)
{
    while (__atomic_exchange_n(&lock_word, 1, __ATOMIC_ACQUIRE))
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
    if (!initialized) {
        for (int i = 0; i < SLOTS; i++) slots[i].fd = -1;
        initialized = 1;
    }
}
static void unlock(void) { __atomic_store_n(&lock_word, 0, __ATOMIC_RELEASE); }

static void identity(int fd, uint64_t *dev, uint64_t *ino)
{
    struct { uint64_t dev, ino; unsigned char rest[112]; } st;
    if (raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0) < 0) st.dev = st.ino = 0;
    *dev = st.dev;
    *ino = st.ino;
}

/* Under the lock: the FD's slot, made when create (NULL when full). A slot
 * of an earlier object under the same number (closed where this code did
 * not see it) is dropped. */
static struct async_fd *slot(int fd, int create)
{
    uint64_t dev, ino;
    identity(fd, &dev, &ino);
    struct async_fd *free_slot = 0;
    for (int i = 0; i < SLOTS; i++) {
        if (slots[i].fd == fd && (slots[i].dev != dev || slots[i].ino != ino)) slots[i].fd = -1;
        if (slots[i].fd == fd) return &slots[i];
        if (slots[i].fd < 0 && !free_slot) free_slot = &slots[i];
    }
    if (!create || !free_slot) return 0;
    *free_slot = (struct async_fd){.fd = fd, .dev = dev, .ino = ino};
    return free_slot;
}

/* The kernel has no such support for this object (not a bad FD). */
static int unsupported(long rc, int fd)
{
    return (rc == -ENOTTY || rc == -EINVAL || rc == -EOPNOTSUPP || rc == -EACCES) &&
           raw_syscall(__NR_fcntl, fd, 1 /* F_GETFD */, 0, 0, 0, 0) >= 0;
}

static long kept(int fd, long rc, void (*store)(struct async_fd *, const long *), const long *a)
{
    if (!unsupported(rc, fd)) return rc;
    lock();
    struct async_fd *s = slot(fd, 1);
    if (s) store(s, a);
    unlock();
    return s ? 0 : rc;
}
static void store_fioasync(struct async_fd *s, const long *a) { s->async = *(const int *)a[2] != 0; }
static void store_owner(struct async_fd *s, const long *a)
{
    s->owner_set = 1;
    s->owner.type = 0 /* F_OWNER_TID */;
    s->owner.pid = (int)a[2];
    if (s->owner.pid < 0) { s->owner.type = 2 /* F_OWNER_PGRP */; s->owner.pid = -s->owner.pid; }
    else s->owner.type = 1 /* F_OWNER_PID */;
}
static void store_owner_ex(struct async_fd *s, const long *a)
{
    const int *ex = (const int *)a[2];
    s->owner_set = 1;
    s->owner.type = ex[0];
    s->owner.pid = ex[1];
}
static void store_sig(struct async_fd *s, const long *a) { s->sig_set = 1; s->sig = (int)a[2]; }

int async_io_syscall(long number, long a[6], long *result)
{
    int fd = (int)a[0];
    if (number == __NR_close || number == __NR_dup3) {
        /* The number's settings go with its object (dup3: the target's). */
        int gone = number == __NR_close ? fd : (int)a[1];
        if (__atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) {
            lock();
            for (int i = 0; i < SLOTS; i++)
                if (slots[i].fd == gone) slots[i].fd = -1;
            unlock();
        }
        return 0;
    }
    if (number == __NR_ioctl && (unsigned long)a[1] == FIOASYNC_) {
        if (!a[2]) return 0;
        *result = kept(fd, raw_syscall(number, a[0], a[1], a[2], 0, 0, 0), store_fioasync, a);
        return 1;
    }
    if (number != __NR_fcntl) return 0;
    long command = a[1];
    switch (command) {
    case F_SETFL_: {
        long rc = raw_syscall(number, fd, command, a[2], 0, 0, 0);
        if (rc == -EINVAL && (a[2] & O_ASYNC_) && raw_syscall(number, fd, 1 /* F_GETFD */, 0, 0, 0, 0) >= 0)
            rc = raw_syscall(number, fd, command, a[2] & ~(long)O_ASYNC_, 0, 0, 0);
        if (rc == 0) {
            /* O_ASYNC as asked, whether the kernel kept it (pipes), ignored
             * it (TCP) or refused it (UNIX sockets). */
            lock();
            struct async_fd *s = slot(fd, (a[2] & O_ASYNC_) != 0);
            if (s) s->async = (a[2] & O_ASYNC_) != 0;
            unlock();
        }
        *result = rc;
        return 1;
    }
    case F_GETFL_: {
        long rc = raw_syscall(number, fd, command, 0, 0, 0, 0);
        if (rc >= 0 && __atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) {
            lock();
            struct async_fd *s = slot(fd, 0);
            if (s) rc = s->async ? rc | O_ASYNC_ : rc & ~(long)O_ASYNC_;
            unlock();
        }
        *result = rc;
        return 1;
    }
    case F_SETOWN_:
        *result = kept(fd, raw_syscall(number, fd, command, a[2], 0, 0, 0), store_owner, a);
        return 1;
    case F_SETOWN_EX_:
        if (!a[2]) return 0;
        *result = kept(fd, raw_syscall(number, fd, command, a[2], 0, 0, 0), store_owner_ex, a);
        return 1;
    case F_SETSIG_:
        *result = kept(fd, raw_syscall(number, fd, command, a[2], 0, 0, 0), store_sig, a);
        return 1;
    case F_GETOWN_: case F_GETOWN_EX_: case F_GETSIG_: {
        if (!__atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) return 0;
        lock();
        struct async_fd *s = slot(fd, 0);
        int have = s && (command == F_GETSIG_ ? s->sig_set : s->owner_set);
        struct async_fd copy = have ? *s : (struct async_fd){0};
        unlock();
        if (!have) return 0;
        if (command == F_GETSIG_) *result = copy.sig;
        else if (command == F_GETOWN_) *result = copy.owner.type == 2 ? -copy.owner.pid : copy.owner.pid;
        else if (!a[2]) *result = -EFAULT;
        else { ((int *)a[2])[0] = copy.owner.type; ((int *)a[2])[1] = copy.owner.pid; *result = 0; }
        return 1;
    }
    }
    return 0;
}
