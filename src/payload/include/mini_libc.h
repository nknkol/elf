#ifndef MINI_LIBC_H
#define MINI_LIBC_H

long sys_write(int fd, const void *buf, unsigned long count);
unsigned long sys_strlen(const char *s);

#endif