#ifndef SYSCALL_HOOKS_H
#define SYSCALL_HOOKS_H

/* Arch-specific syscall numbers are provided by arch/$(ARCH)/syscall_nums.h */
#include "syscall_nums.h"

/* Common hook dispatcher; args is an array of 6 syscall arguments. */
long syscall_handle_common(long sys_no, long args[6]);

#endif /* SYSCALL_HOOKS_H */
