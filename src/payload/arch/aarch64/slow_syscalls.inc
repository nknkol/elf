/* Shared routing inventory, deliberately without an include guard.
 * SLOW_SYSCALL is supplied by assembly/tests. Selection is not implementation.
 * clone/rt_sigreturn/exit/exit_group must stay outside this list.
 * Non-filesystem ordinary calls and unknown numbers retain fast passthrough.
 */
#ifdef __NR_getcwd
SLOW_SYSCALL(__NR_getcwd)
#endif
#ifdef __NR_rt_sigaction
SLOW_SYSCALL(__NR_rt_sigaction)
#endif
#ifdef __NR_mknodat
SLOW_SYSCALL(__NR_mknodat)
#endif
#ifdef __NR_faccessat
SLOW_SYSCALL(__NR_faccessat)
#endif
#ifdef __NR_fchdir
SLOW_SYSCALL(__NR_fchdir)
#endif
#ifdef __NR_chdir
SLOW_SYSCALL(__NR_chdir)
#endif
#ifdef __NR_mkdirat
SLOW_SYSCALL(__NR_mkdirat)
#endif
#ifdef __NR_unlinkat
SLOW_SYSCALL(__NR_unlinkat)
#endif
#ifdef __NR_linkat
SLOW_SYSCALL(__NR_linkat)
#endif
#ifdef __NR_renameat2
SLOW_SYSCALL(__NR_renameat2)
#endif
#ifdef __NR_renameat
SLOW_SYSCALL(__NR_renameat)
#endif
#ifdef __NR_fchmod
SLOW_SYSCALL(__NR_fchmod)
#endif
#ifdef __NR_fchmodat
SLOW_SYSCALL(__NR_fchmodat)
#endif
#ifdef __NR_fchownat
SLOW_SYSCALL(__NR_fchownat)
#endif
#ifdef __NR_fchown
SLOW_SYSCALL(__NR_fchown)
#endif
#ifdef __NR_setuid
SLOW_SYSCALL(__NR_setuid)
#endif
#ifdef __NR_setgid
SLOW_SYSCALL(__NR_setgid)
#endif
#ifdef __NR_setreuid
SLOW_SYSCALL(__NR_setreuid)
#endif
#ifdef __NR_setregid
SLOW_SYSCALL(__NR_setregid)
#endif
#ifdef __NR_setresuid
SLOW_SYSCALL(__NR_setresuid)
#endif
#ifdef __NR_setresgid
SLOW_SYSCALL(__NR_setresgid)
#endif
#ifdef __NR_setfsuid
SLOW_SYSCALL(__NR_setfsuid)
#endif
#ifdef __NR_setfsgid
SLOW_SYSCALL(__NR_setfsgid)
#endif
#ifdef __NR_setgroups
SLOW_SYSCALL(__NR_setgroups)
#endif
#ifdef __NR_getuid
SLOW_SYSCALL(__NR_getuid)
#endif
#ifdef __NR_geteuid
SLOW_SYSCALL(__NR_geteuid)
#endif
#ifdef __NR_getgid
SLOW_SYSCALL(__NR_getgid)
#endif
#ifdef __NR_getegid
SLOW_SYSCALL(__NR_getegid)
#endif
#ifdef __NR_getresuid
SLOW_SYSCALL(__NR_getresuid)
#endif
#ifdef __NR_getresgid
SLOW_SYSCALL(__NR_getresgid)
#endif
#ifdef __NR_getgroups
SLOW_SYSCALL(__NR_getgroups)
#endif
#ifdef __NR_openat
SLOW_SYSCALL(__NR_openat)
#endif
#ifdef __NR_close
SLOW_SYSCALL(__NR_close)
#endif
#ifdef __NR_write
SLOW_SYSCALL(__NR_write)
#endif
#ifdef __NR_symlinkat
SLOW_SYSCALL(__NR_symlinkat)
#endif
#ifdef __NR_readlinkat
SLOW_SYSCALL(__NR_readlinkat)
#endif
#ifdef __NR_getdents64
SLOW_SYSCALL(__NR_getdents64)
#endif
#ifdef __NR_newfstatat
SLOW_SYSCALL(__NR_newfstatat)
#endif
#ifdef __NR_statfs
SLOW_SYSCALL(__NR_statfs)
#endif
#ifdef __NR_fstatfs
SLOW_SYSCALL(__NR_fstatfs)
#endif
#ifdef __NR_utimensat
SLOW_SYSCALL(__NR_utimensat)
#endif
#ifdef __NR_execve
SLOW_SYSCALL(__NR_execve)
#endif
#ifdef __NR_execveat
SLOW_SYSCALL(__NR_execveat)
#endif
#ifdef __NR_mprotect
SLOW_SYSCALL(__NR_mprotect)
#endif
#ifdef __NR_mmap
SLOW_SYSCALL(__NR_mmap)
#endif
#ifdef __NR_rseq
SLOW_SYSCALL(__NR_rseq)
#endif
#ifdef __NR_getrandom
SLOW_SYSCALL(__NR_getrandom)
#endif
#ifdef __NR_membarrier
SLOW_SYSCALL(__NR_membarrier)
#endif
#ifdef __NR_prctl
SLOW_SYSCALL(__NR_prctl)
#endif
#ifdef __NR_faccessat2
SLOW_SYSCALL(__NR_faccessat2)
#endif
#ifdef __NR_statx
SLOW_SYSCALL(__NR_statx)
#endif
#ifdef __NR_clone3
SLOW_SYSCALL(__NR_clone3)
#endif
#ifdef __NR_read
SLOW_SYSCALL(__NR_read)
#endif
#ifdef __NR_readv
SLOW_SYSCALL(__NR_readv)
#endif
#ifdef __NR_writev
SLOW_SYSCALL(__NR_writev)
#endif
#ifdef __NR_pread64
SLOW_SYSCALL(__NR_pread64)
#endif
#ifdef __NR_pwrite64
SLOW_SYSCALL(__NR_pwrite64)
#endif
#ifdef __NR_preadv
SLOW_SYSCALL(__NR_preadv)
#endif
#ifdef __NR_pwritev
SLOW_SYSCALL(__NR_pwritev)
#endif
#ifdef __NR_preadv2
SLOW_SYSCALL(__NR_preadv2)
#endif
#ifdef __NR_pwritev2
SLOW_SYSCALL(__NR_pwritev2)
#endif
#ifdef __NR_dup
SLOW_SYSCALL(__NR_dup)
#endif
#ifdef __NR_dup3
SLOW_SYSCALL(__NR_dup3)
#endif
#ifdef __NR_fcntl
SLOW_SYSCALL(__NR_fcntl)
#endif
#ifdef __NR_lseek
SLOW_SYSCALL(__NR_lseek)
#endif
#ifdef __NR_fstat
SLOW_SYSCALL(__NR_fstat)
#endif
#ifdef __NR_truncate
SLOW_SYSCALL(__NR_truncate)
#endif
#ifdef __NR_ftruncate
SLOW_SYSCALL(__NR_ftruncate)
#endif
#ifdef __NR_fallocate
SLOW_SYSCALL(__NR_fallocate)
#endif
#ifdef __NR_fsync
SLOW_SYSCALL(__NR_fsync)
#endif
#ifdef __NR_fdatasync
SLOW_SYSCALL(__NR_fdatasync)
#endif
#ifdef __NR_syncfs
SLOW_SYSCALL(__NR_syncfs)
#endif
#ifdef __NR_sync_file_range
SLOW_SYSCALL(__NR_sync_file_range)
#endif
#ifdef __NR_flock
SLOW_SYSCALL(__NR_flock)
#endif
#ifdef __NR_ioctl
SLOW_SYSCALL(__NR_ioctl)
#endif
#ifdef __NR_sendfile
SLOW_SYSCALL(__NR_sendfile)
#endif
#ifdef __NR_copy_file_range
SLOW_SYSCALL(__NR_copy_file_range)
#endif
#ifdef __NR_splice
SLOW_SYSCALL(__NR_splice)
#endif
#ifdef __NR_tee
SLOW_SYSCALL(__NR_tee)
#endif
#ifdef __NR_vmsplice
SLOW_SYSCALL(__NR_vmsplice)
#endif
#ifdef __NR_getxattr
SLOW_SYSCALL(__NR_getxattr)
#endif
#ifdef __NR_lgetxattr
SLOW_SYSCALL(__NR_lgetxattr)
#endif
#ifdef __NR_fgetxattr
SLOW_SYSCALL(__NR_fgetxattr)
#endif
#ifdef __NR_setxattr
SLOW_SYSCALL(__NR_setxattr)
#endif
#ifdef __NR_lsetxattr
SLOW_SYSCALL(__NR_lsetxattr)
#endif
#ifdef __NR_fsetxattr
SLOW_SYSCALL(__NR_fsetxattr)
#endif
#ifdef __NR_listxattr
SLOW_SYSCALL(__NR_listxattr)
#endif
#ifdef __NR_llistxattr
SLOW_SYSCALL(__NR_llistxattr)
#endif
#ifdef __NR_flistxattr
SLOW_SYSCALL(__NR_flistxattr)
#endif
#ifdef __NR_removexattr
SLOW_SYSCALL(__NR_removexattr)
#endif
#ifdef __NR_lremovexattr
SLOW_SYSCALL(__NR_lremovexattr)
#endif
#ifdef __NR_fremovexattr
SLOW_SYSCALL(__NR_fremovexattr)
#endif
#ifdef __NR_openat2
SLOW_SYSCALL(__NR_openat2)
#endif
#ifdef __NR_open_by_handle_at
SLOW_SYSCALL(__NR_open_by_handle_at)
#endif
#ifdef __NR_name_to_handle_at
SLOW_SYSCALL(__NR_name_to_handle_at)
#endif
#ifdef __NR_io_uring_setup
SLOW_SYSCALL(__NR_io_uring_setup)
#endif
#ifdef __NR_io_uring_enter
SLOW_SYSCALL(__NR_io_uring_enter)
#endif
#ifdef __NR_io_uring_register
SLOW_SYSCALL(__NR_io_uring_register)
#endif
#ifdef __NR_io_setup
SLOW_SYSCALL(__NR_io_setup)
#endif
#ifdef __NR_io_destroy
SLOW_SYSCALL(__NR_io_destroy)
#endif
#ifdef __NR_io_submit
SLOW_SYSCALL(__NR_io_submit)
#endif
#ifdef __NR_io_cancel
SLOW_SYSCALL(__NR_io_cancel)
#endif
#ifdef __NR_io_getevents
SLOW_SYSCALL(__NR_io_getevents)
#endif
#ifdef __NR_io_pgetevents
SLOW_SYSCALL(__NR_io_pgetevents)
#endif
#ifdef __NR_bind
SLOW_SYSCALL(__NR_bind)
#endif
#ifdef __NR_connect
SLOW_SYSCALL(__NR_connect)
#endif
#ifdef __NR_sendmsg
SLOW_SYSCALL(__NR_sendmsg)
#endif
#ifdef __NR_recvmsg
SLOW_SYSCALL(__NR_recvmsg)
#endif
#ifdef __NR_sendmmsg
SLOW_SYSCALL(__NR_sendmmsg)
#endif
#ifdef __NR_recvmmsg
SLOW_SYSCALL(__NR_recvmmsg)
#endif
#ifdef __NR_mount
SLOW_SYSCALL(__NR_mount)
#endif
#ifdef __NR_umount2
SLOW_SYSCALL(__NR_umount2)
#endif
#ifdef __NR_pivot_root
SLOW_SYSCALL(__NR_pivot_root)
#endif
#ifdef __NR_chroot
SLOW_SYSCALL(__NR_chroot)
#endif
#ifdef __NR_unshare
SLOW_SYSCALL(__NR_unshare)
#endif
#ifdef __NR_setns
SLOW_SYSCALL(__NR_setns)
#endif
#ifdef __NR_fsopen
SLOW_SYSCALL(__NR_fsopen)
#endif
#ifdef __NR_fsconfig
SLOW_SYSCALL(__NR_fsconfig)
#endif
#ifdef __NR_fsmount
SLOW_SYSCALL(__NR_fsmount)
#endif
#ifdef __NR_fspick
SLOW_SYSCALL(__NR_fspick)
#endif
#ifdef __NR_open_tree
SLOW_SYSCALL(__NR_open_tree)
#endif
#ifdef __NR_move_mount
SLOW_SYSCALL(__NR_move_mount)
#endif
#ifdef __NR_close_range
SLOW_SYSCALL(__NR_close_range)
#endif
#ifdef __NR_memfd_create
SLOW_SYSCALL(__NR_memfd_create)
#endif
#ifdef __NR_munmap
SLOW_SYSCALL(__NR_munmap)
#endif
#ifdef __NR_mremap
SLOW_SYSCALL(__NR_mremap)
#endif
#ifdef __NR_madvise
SLOW_SYSCALL(__NR_madvise)
#endif
#ifdef __NR_process_vm_readv
SLOW_SYSCALL(__NR_process_vm_readv)
#endif
#ifdef __NR_process_vm_writev
SLOW_SYSCALL(__NR_process_vm_writev)
#endif
#ifdef __NR_pidfd_open
SLOW_SYSCALL(__NR_pidfd_open)
#endif
#ifdef __NR_pidfd_getfd
SLOW_SYSCALL(__NR_pidfd_getfd)
#endif

#ifdef __NR_inotify_add_watch
SLOW_SYSCALL(__NR_inotify_add_watch)
#endif
