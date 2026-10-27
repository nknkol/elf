/* Unsupported direct FD creators in FD_EXPERIMENT only. Keep dispatch and
 * denial together: routing a call slowly does not itself track its result.
 * Not a complete allowlist (ioctl/ancillary/lifecycle gaps remain). */
#ifdef __NR_fanotify_init
FD_UNSUPPORTED(__NR_fanotify_init)
#endif
#ifdef __NR_userfaultfd
FD_UNSUPPORTED(__NR_userfaultfd)
#endif
#ifdef __NR_perf_event_open
FD_UNSUPPORTED(__NR_perf_event_open)
#endif
#ifdef __NR_bpf
FD_UNSUPPORTED(__NR_bpf)
#endif
#ifdef __NR_mq_open
FD_UNSUPPORTED(__NR_mq_open)
#endif
#ifdef __NR_open_tree
FD_UNSUPPORTED(__NR_open_tree)
#endif
#ifdef __NR_fsopen
FD_UNSUPPORTED(__NR_fsopen)
#endif
#ifdef __NR_fsmount
FD_UNSUPPORTED(__NR_fsmount)
#endif
#ifdef __NR_fspick
FD_UNSUPPORTED(__NR_fspick)
#endif
#ifdef __NR_open_by_handle_at
FD_UNSUPPORTED(__NR_open_by_handle_at)
#endif
#ifdef __NR_seccomp
FD_UNSUPPORTED(__NR_seccomp)
#endif
#ifdef __NR_io_uring_setup
FD_UNSUPPORTED(__NR_io_uring_setup)
#endif
#ifdef __NR_landlock_create_ruleset
FD_UNSUPPORTED(__NR_landlock_create_ruleset)
#endif
#ifdef __NR_memfd_secret
FD_UNSUPPORTED(__NR_memfd_secret)
#endif
