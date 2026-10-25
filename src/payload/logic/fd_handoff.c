/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <errno.h>
#include <limits.h>
#include <linux/fcntl.h>
#include <linux/memfd.h>
#include "fd_handoff.h"
extern long raw_syscall(long, long, long, long, long, long, long);
#define HANDOFF_SEALS (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)

long fd_handoff_create(const struct fd_table *t, void *scratch, size_t capacity)
{
    size_t bytes;
    int rc = fd_snapshot_export(t, scratch, capacity, &bytes);
    if (rc) return rc;
    long fd = raw_syscall(__NR_memfd_create, (long)"elf-fd-state",
                          MFD_CLOEXEC | MFD_ALLOW_SEALING, 0, 0, 0, 0);
    if (fd < 0) return fd;
    size_t done = 0;
    long ret;
    while (done < bytes) {
        ret = raw_syscall(__NR_write, fd, (long)((char *)scratch + done),
                          bytes - done, 0, 0, 0);
        if (ret == -EINTR) continue;
        if (ret <= 0) { if (!ret) ret = -EIO; goto fail; }
        done += (size_t)ret;
    }
    ret = raw_syscall(__NR_fcntl, fd, F_ADD_SEALS, HANDOFF_SEALS, 0, 0, 0);
    if (ret < 0) goto fail;
    return fd;
 fail:
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return ret;
}

int fd_handoff_restore(struct fd_table *t, int fd, void *scratch, size_t capacity)
{
    if (!scratch) return -EINVAL;
    if (capacity < FD_SNAPSHOT_HEADER_BYTES) return -ENOSPC;
    if (capacity > LONG_MAX) return -EOVERFLOW;
    long ret = raw_syscall(__NR_fcntl, fd, F_GET_SEALS, 0, 0, 0, 0);
    if (ret < 0) return (int)ret;
    if ((ret & HANDOFF_SEALS) != HANDOFF_SEALS) return -EINVAL;
    size_t done = 0;
    while (done < capacity) {
        ret = raw_syscall(__NR_pread64, fd, (long)((char *)scratch + done),
                          capacity - done, done, 0, 0);
        if (ret == -EINTR) continue;
        if (ret < 0) return (int)ret;
        if (!ret) return fd_snapshot_import(t, scratch, done);
        done += (size_t)ret;
    }
    /* An exact-capacity snapshot is valid only if no extra byte follows. */
    unsigned char extra;
    do {
        ret = raw_syscall(__NR_pread64, fd, (long)&extra, 1, done, 0, 0);
    } while (ret == -EINTR);
    if (ret < 0) return (int)ret;
    if (ret) return -ENOSPC;
    return fd_snapshot_import(t, scratch, done);
}
