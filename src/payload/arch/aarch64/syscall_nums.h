#ifndef SYSCALL_NUMS_H
#define SYSCALL_NUMS_H

/* AArch64 syscall numbers */
#define SYS_getcwd       17
#define SYS_mknodat      33
#define SYS_mkdirat      34
#define SYS_unlinkat     35
#define SYS_linkat       37
#define SYS_renameat     38
#define SYS_faccessat    48
#define SYS_chdir        49
#define SYS_openat       56
#define SYS_close        57
#define SYS_read         63
#define SYS_write        64
#define SYS_symlinkat    36
#define SYS_readlinkat   78
#define SYS_newfstatat   79
#define SYS_exit         93
#define SYS_exit_group   94
#define SYS_rt_sigreturn 139
#define SYS_execve       221
#define SYS_mprotect     226

#endif /* SYSCALL_NUMS_H */
