#include "mini_libc.h"
#include "syscall_nums.h"

long sys_write(int fd, const void *buf, unsigned long count)
{
    register long x8 asm("x8") = SYS_write;
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = (long)buf;
    register long x2 asm("x2") = count;
    register long ret asm("x0");

    asm volatile(
        "svc #0"
        : "=r"(ret)
        : "r"(x8), "r"(x0), "r"(x1), "r"(x2)
        : "memory", "cc"
    );

    return ret;
}

/* Basic strlen for safety if needed */
unsigned long sys_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return p - s;
}
