#ifndef SYSCALL_NUMS_H
#define SYSCALL_NUMS_H

/* Target headers are the authority for AArch64 ABI numbers (also in .S). */
#include <asm/unistd.h>
#define SYS_getcwd           __NR_getcwd
#define SYS_mknodat          __NR_mknodat
#define SYS_mkdirat          __NR_mkdirat
#define SYS_unlinkat         __NR_unlinkat
#define SYS_linkat           __NR_linkat
#define SYS_renameat         __NR_renameat
#define SYS_renameat2        __NR_renameat2
#define SYS_faccessat        __NR_faccessat
#define SYS_chdir            __NR_chdir
#define SYS_fchdir           __NR_fchdir
#define SYS_fchmod           __NR_fchmod
#define SYS_fchmodat         __NR_fchmodat
#define SYS_fchownat         __NR_fchownat
#define SYS_fchown           __NR_fchown
#define SYS_setregid         __NR_setregid
#define SYS_setgid           __NR_setgid
#define SYS_setreuid         __NR_setreuid
#define SYS_setuid           __NR_setuid
#define SYS_setresuid        __NR_setresuid
#define SYS_getresuid        __NR_getresuid
#define SYS_setresgid        __NR_setresgid
#define SYS_getresgid        __NR_getresgid
#define SYS_setfsuid         __NR_setfsuid
#define SYS_setfsgid         __NR_setfsgid
#define SYS_setpgid          __NR_setpgid
#define SYS_getpgid          __NR_getpgid
#define SYS_getsid           __NR_getsid
#define SYS_setsid           __NR_setsid
#define SYS_getgroups        __NR_getgroups
#define SYS_setgroups        __NR_setgroups
#define SYS_uname            __NR_uname
#define SYS_getpid           __NR_getpid
#define SYS_getppid          __NR_getppid
#define SYS_getuid           __NR_getuid
#define SYS_geteuid          __NR_geteuid
#define SYS_getgid           __NR_getgid
#define SYS_getegid          __NR_getegid
#define SYS_openat           __NR_openat
#define SYS_close            __NR_close
#define SYS_read             __NR_read
#define SYS_write            __NR_write
#define SYS_getdents64       __NR_getdents64
#define SYS_symlinkat        __NR_symlinkat
#define SYS_readlinkat       __NR_readlinkat
#define SYS_newfstatat       __NR_newfstatat
#define SYS_statfs           __NR_statfs
#define SYS_fstatfs          __NR_fstatfs
#define SYS_utimensat        __NR_utimensat
#define SYS_rt_sigaction     __NR_rt_sigaction
#define SYS_rt_sigreturn     __NR_rt_sigreturn
#define SYS_exit             __NR_exit
#define SYS_exit_group       __NR_exit_group
#define SYS_mmap             __NR_mmap
#define SYS_execve           __NR_execve
#define SYS_execveat         __NR_execveat
#define SYS_mprotect         __NR_mprotect
/* 新增调试用 Syscall ID */
#define SYS_prctl            __NR_prctl
#define SYS_getrandom        __NR_getrandom
#define SYS_membarrier       __NR_membarrier
#define SYS_statx            __NR_statx
#define SYS_rseq             __NR_rseq
#define SYS_clone            __NR_clone
#define SYS_clone3           __NR_clone3
#define SYS_faccessat2       __NR_faccessat2

#define SYS_openat2 __NR_openat2
#define SYS_open_by_handle_at __NR_open_by_handle_at
#define SYS_io_uring_enter __NR_io_uring_enter
#define SYS_io_uring_register __NR_io_uring_register

#endif /* SYSCALL_NUMS_H */
