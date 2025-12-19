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
#define SYS_fchmod       52
#define SYS_fchmodat     53
#define SYS_fchownat     54
#define SYS_fchown       55
#define SYS_setregid     143
#define SYS_setgid       144
#define SYS_setreuid     145
#define SYS_setuid       146
#define SYS_setresuid    147
#define SYS_getresuid    148
#define SYS_setresgid    149
#define SYS_getresgid    150
#define SYS_setfsuid     151
#define SYS_setfsgid     152
#define SYS_setpgid      154
#define SYS_getpgid      155
#define SYS_getsid       156
#define SYS_setsid       157
#define SYS_getgroups    158
#define SYS_setgroups    159
#define SYS_getpid       172
#define SYS_getppid      173
#define SYS_getuid       174
#define SYS_geteuid      175
#define SYS_getgid       176
#define SYS_getegid      177
#define SYS_openat       56
#define SYS_close        57
#define SYS_read         63
#define SYS_write        64
#define SYS_symlinkat    36
#define SYS_readlinkat   78
#define SYS_newfstatat   79
#define SYS_utimensat    88
#define SYS_exit         93
#define SYS_exit_group   94
#define SYS_mmap         222
#define SYS_rt_sigreturn 139
#define SYS_execve       221
#define SYS_execveat     281
#define SYS_mprotect     226
/* 新增调试用 Syscall ID */
#define SYS_prctl        167
#define SYS_getrandom    278
#define SYS_membarrier   283
#define SYS_statx        291
#define SYS_rseq         293
#define SYS_clone3       435
#define SYS_faccessat2   439

#endif /* SYSCALL_NUMS_H */
