/* PR_GET_AUXV for the guest image, not the kernel-executed loader. */
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include "config.h"
#include "proot_bridge.h"
extern long raw_syscall(long, long, long, long, long, long, long);

long proot_get_auxv(long a[6])
{
    if (a[3] || a[4]) return -EINVAL;
    size_t size = g_payload_config.guest_auxv_bytes;
    if (!size || size > sizeof(g_payload_config.guest_auxv)) return -EOPNOTSUPP;
    size_t count = (unsigned long)a[2] < size ? (unsigned long)a[2] : size;
    if (!count) return (long)size;
    /* Use kernel copying to the guest buffer, including EFAULT handling.
     * No retained FD or mutable file offset is shared between callers. This
     * initialization-only interface trades a temporary memfd for fault safety. */
    long fd = raw_syscall(__NR_memfd_create, (long)"guest-auxv", 1, 0, 0, 0, 0);
    if (fd < 0) return fd;
    long ret = raw_syscall(__NR_write, fd, (long)g_payload_config.guest_auxv,
                           (long)size, 0, 0, 0);
    if (ret == (long)size) {
        ret = raw_syscall(__NR_pread64, fd, a[1], (long)count, 0, 0, 0);
        if (ret == (long)count) ret = (long)size;
        else if (ret >= 0) ret = -EFAULT;
    } else if (ret >= 0) ret = -EIO;
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return ret;
}
