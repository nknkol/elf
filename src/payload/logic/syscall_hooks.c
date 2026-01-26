#include "syscall_hooks.h"
#include "mini_libc.h"
#include "config.h"
#include "exec_handler.h"
#include "execve_utils.h"
#include "path_rewrite.h"
#include "syscall_nums.h"
#include "hook_runtime.h"
#include "log.h"
#include "utils.h"
#include "vfs_core.h"

#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define PROT_EXEC       0x4
#define MAP_PRIVATE     0x02
#define MAP_FIXED       0x10
#define MAP_ANON        0x20
#define MAP_ANONYMOUS   MAP_ANON
#define SYS_pread64     67
#define SYS_munmap      215
#define SYS_prctl       167
#ifndef EPERM
#define EPERM           1
#endif
#ifndef EXDEV
#define EXDEV           18
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP      95
#endif
#ifndef ENOMEM
#define ENOMEM          12
#endif
#ifndef EINVAL
#define EINVAL          22
#endif
#ifndef ENOSYS
#define ENOSYS          38
#endif
#ifndef EACCES
#define EACCES          13
#endif
#define PR_JIT_WORKAROUND 0x6a6974
#ifndef SIGSEGV
#define SIGSEGV 11
#endif

#define DEBUG_LOG(msg) LOG_DEBUG(msg)

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);
unsigned long sys_strlen(const char *s);
extern payload_config_t g_payload_config;
extern void _start(void);

static inline long do_syscall(long sys_no, long *a) {
    return raw_syscall(sys_no, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static long read_into_region(int fd, void *dst, unsigned long len, long off)
{
    unsigned char *p = (unsigned char *)dst;
    unsigned long remaining = len;
    long offset = off;

    while (remaining > 0) {
        unsigned long chunk = remaining > 4096 ? 4096 : remaining;
        long n = raw_syscall(SYS_pread64, fd, (long)p, (long)chunk, offset, 0, 0);
        if (n < 0)
            return n;
        if (n == 0) {
            zero_region(p, remaining);
            break;
        }
        p += n;
        offset += n;
        remaining -= (unsigned long)n;
        if (n < (long)chunk) {
            zero_region(p, remaining);
            break;
        }
    }
    return 0;
}

static long mmap_exec_anon_fallback(long *args)
{
    void *req_addr = (void *)args[0];
    unsigned long len = (unsigned long)args[1];
    int prot = (int)args[2];
    int flags = (int)args[3];
    int fd = (int)args[4];
    long off = args[5];

    int anon_flags = flags | MAP_ANONYMOUS;
    void *mapped = (void *)raw_syscall(SYS_mmap, (long)req_addr, (long)len,
                                       PROT_READ | PROT_WRITE, anon_flags, -1, 0);
    if ((long)mapped < 0)
        return (long)mapped;

    long rc = read_into_region(fd, mapped, len, off);
    if (rc < 0) {
        raw_syscall(SYS_munmap, (long)mapped, (long)len, 0, 0, 0, 0);
        return rc;
    }

    int need_prctl = (prot & PROT_EXEC) && is_harmonyos();
    if (need_prctl)
        raw_syscall(SYS_prctl, PR_JIT_WORKAROUND, 0, 0, 0, 0, 0);
    long mp = raw_syscall(SYS_mprotect, (long)mapped, (long)len, prot, 0, 0, 0);
    if (need_prctl)
        raw_syscall(SYS_prctl, PR_JIT_WORKAROUND, 0, 1, 0, 0, 0);

    if (mp < 0) {
        raw_syscall(SYS_munmap, (long)mapped, (long)len, 0, 0, 0, 0);
        return mp;
    }

    if (prot & PROT_EXEC)
        install_hook(mapped, len, (void *)&_start, 0);

    return (long)mapped;
}

struct syscall_common_scratch {
    char new_path[CONFIG_MAX_PATH];
    char new_path2[CONFIG_MAX_PATH];
    char out_path[CONFIG_MAX_PATH];
    char resolved[CONFIG_MAX_PATH];
    char resolved_target[CONFIG_MAX_PATH];
    char resolved_link[CONFIG_MAX_PATH];
    char bounce[CONFIG_MAX_PATH];
};

static struct syscall_common_scratch *syscall_common_scratch_alloc(void)
{
    size_t sz = sizeof(struct syscall_common_scratch);
    void *p = (void *)raw_syscall(SYS_mmap, 0, (long)sz,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)p < 0)
        return NULL;
    return (struct syscall_common_scratch *)p;
}

static void syscall_common_scratch_free(struct syscall_common_scratch *scratch)
{
    if (!scratch)
        return;
    raw_syscall(SYS_munmap, (long)scratch, (long)sizeof(*scratch), 0, 0, 0, 0);
}

long syscall_handle_common(long sys_no, long args[6]) {
    long ret;
    struct syscall_common_scratch *scratch = syscall_common_scratch_alloc();
    if (!scratch)
        return -ENOMEM;

    switch (sys_no) {
        case SYS_getcwd:
            DEBUG_LOG("[Payload] getcwd\n");
            ret = do_syscall(sys_no, args);
            if (ret > 0 && (const char *)args[0]) {
                const char *host_path = (const char *)args[0];
                const char *guest_path = vfs_reverse_path(host_path,
                                                          scratch->out_path,
                                                          sizeof(scratch->out_path));
                size_t guest_len = sys_strlen(guest_path);
                if (guest_len + 1 <= (size_t)args[1]) {
                    small_copy((char *)args[0], guest_path);
                    ret = guest_len;
                }
            }
            break;

        case SYS_chdir: {
            DEBUG_LOG("[Payload] chdir -> VFS\n");
            const char *virt_path = (const char *)args[0];
            if (virt_path) {
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] chdir path ", virt_path, res.path);
                args[0] = (long)res.path;
            }
            ret = do_syscall(sys_no, args);
            break;
        }

        /* Fakeroot Phase1/2: Identity faking via VFS core */
        case SYS_setuid:
        case SYS_setgid:
        case SYS_setreuid:
        case SYS_setregid:
        case SYS_setresuid:
        case SYS_setresgid:
        case SYS_setfsuid:
        case SYS_setfsgid:
        case SYS_setgroups:
            DEBUG_LOG("[Payload] fakeroot set* uid/gid -> VFS\n");
            ret = vfs_fake_success();
            break;

        /* Fakeroot Phase2: Information faking via VFS core */
        case SYS_getuid:
            DEBUG_LOG("[Payload] fakeroot getuid -> VFS\n");
            ret = vfs_getuid();
            break;
        case SYS_geteuid:
            DEBUG_LOG("[Payload] fakeroot geteuid -> VFS\n");
            ret = vfs_geteuid();
            break;
        case SYS_getgid:
            DEBUG_LOG("[Payload] fakeroot getgid -> VFS\n");
            ret = vfs_getgid();
            break;
        case SYS_getegid:
            DEBUG_LOG("[Payload] fakeroot getegid -> VFS\n");
            ret = vfs_getegid();
            break;
        case SYS_getresuid: {
            DEBUG_LOG("[Payload] fakeroot getresuid -> VFS\n");
            ret = vfs_getresuid((int *)args[0], (int *)args[1], (int *)args[2]);
            break;
        }
        case SYS_getresgid: {
            DEBUG_LOG("[Payload] fakeroot getresgid -> VFS\n");
            ret = vfs_getresgid((int *)args[0], (int *)args[1], (int *)args[2]);
            break;
        }
        case SYS_getgroups: {
            DEBUG_LOG("[Payload] fakeroot getgroups -> VFS\n");
            ret = vfs_getgroups((int)args[0], (int *)args[1]);
            break;
        }

        case SYS_symlinkat: {
            /* symlinkat(target, newdirfd, linkpath) */
            const char *target_path = (const char*) args[0];
            const char *link_path = (const char*) args[2];

            if (target_path) {
                // The target of a symlink can be anything, so we just rewrite it, don't resolve.
                vfs_path_result_t res = vfs_rewrite_noresolve(target_path,
                                                             scratch->new_path,
                                                             sizeof(scratch->new_path));
                if (res.error) {
                    ret = res.error;
                    break;
                }
                args[0] = (long)res.path;
                log_path_pair("[Payload] symlink target ", target_path, res.path);
            }
            if (link_path) {
                // The destination path should not be resolved.
                vfs_path_result_t res = vfs_resolve(link_path, SYS_unlinkat, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] symlink linkpath ", link_path, res.path);
                args[2] = (long)res.path;
            }
            ret = do_syscall(sys_no, args);
            break;
        }

        case SYS_linkat: {
            const char *old_path = (const char *)args[1];
            const char *new_path = (const char *)args[3];
            
            if (old_path) {
                vfs_path_result_t res = vfs_resolve(old_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] linkat old ", old_path, res.path);
                args[1] = (long)res.path;
            }
            if (new_path) {
                // The destination path should not be resolved.
                vfs_path_result_t res = vfs_resolve(new_path, SYS_unlinkat, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] linkat new ", new_path, res.path);
                args[3] = (long)res.path;
            }

            long link_ret = do_syscall(sys_no, args);
            if (link_ret < 0) {
                long err = -link_ret;
                if (err == EPERM || err == EOPNOTSUPP || err == EXDEV) {
                    DEBUG_LOG("[Payload] linkat fallback -> symlinkat\n");
                    long sym_ret = raw_syscall(SYS_symlinkat, args[1], args[2], args[3], 0, 0, 0);
                    if (sym_ret == 0)
                        link_ret = 0;
                }
            }
            ret = link_ret;
            break;
        }

        case SYS_mkdirat:
        case SYS_mknodat:
        case SYS_unlinkat:
        case SYS_renameat:
        case SYS_openat:
        case SYS_faccessat:
        case SYS_readlinkat:
        case SYS_newfstatat: {
            const char *virt_path = (const char *)args[1];
            if (virt_path) {
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] path arg1 ", virt_path, res.path);
                args[1] = (long)res.path;
            }

            /* Handle syscalls with a second path argument (e.g., renameat) */
            if (sys_no == SYS_renameat) {
                const char *virt_path2 = (const char *)args[3];
                if (virt_path2) {
                    /* For rename's destination, we generally don't follow symlinks.
                     * We pass SYS_unlinkat as a hint to vfs_resolve to prevent resolution. */
                    vfs_path_result_t res2 = vfs_resolve(virt_path2, SYS_unlinkat, args);
                     if (res2.error) {
                        ret = res2.error;
                        break;
                    }
                    log_path_pair("[Payload] path arg3 ", virt_path2, res2.path);
                    args[3] = (long)res2.path;
                }
            }

            /* Handle syscalls that write a path back to the user */
            if (sys_no == SYS_readlinkat && args[2]) {
                char *user_buf = (char *)args[2];
                long user_len = args[3];
                long count = user_len < sizeof(scratch->bounce) ? user_len : sizeof(scratch->bounce) - 1;

                args[2] = (long)scratch->bounce;
                args[3] = count;
                ret = do_syscall(sys_no, args);

                if (ret > 0) {
                    scratch->bounce[ret] = '\0';
                    const char *guest_path = vfs_reverse_path(scratch->bounce,
                                                              scratch->new_path,
                                                              sizeof(scratch->new_path));
                    size_t guest_len = sys_strlen(guest_path);
                    if (guest_len < (size_t)user_len) {
                        safe_cpy(user_buf, user_len, guest_path);
                        ret = guest_len;
                    } else {
                        // Path doesn't fit, what's the right errno? ENAMETOOLONG?
                        // For now, just return the truncated length.
                        safe_cpy(user_buf, user_len - 1, guest_path);
                        user_buf[user_len-1] = '\0';
                        ret = user_len;
                    }
                }
                // Restore original args, just in case.
                args[2] = (long)user_buf;
                args[3] = user_len;
            } else {
                ret = do_syscall(sys_no, args);
            }
            break;
        }

        case SYS_getdents64:
            DEBUG_LOG("[Payload] getdents64 -> VFS\n");
            ret = vfs_getdents64((int)args[0], (void *)args[1], (unsigned int)args[2]);
            break;

        case SYS_fchmodat: {
            DEBUG_LOG("[Payload] fchmodat -> VFS\n");
            const char *virt_path = (const char *)args[1];
            if (virt_path) {
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] fchmodat path ", virt_path, res.path);
                args[1] = (long)res.path;
            }
            ret = vfs_fake_success();
            break;
        }

        case SYS_fchownat: {
            DEBUG_LOG("[Payload] fchownat -> VFS\n");
            if ((const char *)args[1]) {
                const char *virt_path = (const char *)args[1];
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] fchownat path ", virt_path, res.path);
                args[1] = (long)res.path;
            }
            ret = vfs_fake_success();
            break;
        }

        case SYS_utimensat:
            DEBUG_LOG("[Payload] utimensat -> VFS\n");
            if ((const char *)args[1]) {
                const char *virt_path = (const char *)args[1];
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] utimensat path ", virt_path, res.path);
                args[1] = (long)res.path;
            }
            ret = vfs_fake_success();
            break;

        case SYS_fchmod:
            DEBUG_LOG("[Payload] fchmod -> VFS\n");
            ret = vfs_fake_success();
            break;

        case SYS_fchown:
            DEBUG_LOG("[Payload] fchown -> VFS\n");
            ret = vfs_fake_success();
            break;

        case SYS_execve:
            ret = handle_execve_like(sys_no, args, 0);
            break;

        case SYS_execveat:
            ret = handle_execve_like(sys_no, args, 1);
            break;

        case SYS_exit:
        case SYS_exit_group:
            /* Fast path out */
            ret = do_syscall(sys_no, args);
            break;

        case SYS_rt_sigaction: {
            int signum = (int)args[0];
            const void *act = (const void *)args[1];
            void *oact = (void *)args[2];
            size_t sigsetsize = (size_t)args[3];

            if (signum == SIGSEGV && act) {
                DEBUG_LOG("[Payload] Block rt_sigaction(SIGSEGV) to keep loader debugger\n");
                if (oact) {
                    long query = raw_syscall(SYS_rt_sigaction, signum, 0,
                                             (long)oact, (long)sigsetsize, 0, 0);
                    if (query < 0) {
                        ret = query;
                        break;
                    }
                }
                ret = 0;
            } else {
                ret = do_syscall(sys_no, args);
            }
            break;
        }

        case SYS_mprotect:
            DEBUG_LOG("[Payload] mprotect\n");
            /* * 关键修复：防止 Execute-Only Memory (XOM) 导致 Loader 崩溃。
             * 如果目标请求 PROT_EXEC，我们强制加上 PROT_READ，
             * 否则 install_hook() 在扫描内存时会触发 SIGSEGV。
             */
            if (args[2] & PROT_EXEC) {
                args[2] |= PROT_READ; 
                // 可选：如果 install_hook 需要写入，还需要 PROT_WRITE，
                // 但通常 hook 机制会自己处理 mprotect(WRITE)。
                // 主要是防止扫描时挂掉。
            }
            int need_prctl = (args[2] & PROT_EXEC) && is_harmonyos();
            if (need_prctl)
                raw_syscall(SYS_prctl, PR_JIT_WORKAROUND, 0, 0, 0, 0, 0);
            
            ret = do_syscall(sys_no, args);
            if (need_prctl)
                raw_syscall(SYS_prctl, PR_JIT_WORKAROUND, 0, 1, 0, 0, 0);
            
            if (ret == 0 && (args[2] & PROT_EXEC)) {
                install_hook((void *)args[0], (size_t)args[1], (void *)&_start, 0);
            }
            break;

        case SYS_mmap:
            DEBUG_LOG("[Payload] mmap\n");
            /* 同样，防止 mmap 出来的内存不可读 */
            if (args[2] & PROT_EXEC) {
                args[2] |= PROT_READ;
            }
            if ((args[2] & PROT_EXEC) && !(args[3] & MAP_ANON) && (int)args[4] > 0) {
                ret = mmap_exec_anon_fallback(args);
            } else {
                ret = do_syscall(sys_no, args);
                if (ret >= 0 && (args[2] & PROT_EXEC)) {
                    install_hook((void *)ret, (size_t)args[1], (void *)&_start, 0);
                }
            }
            break;

        case SYS_rseq:
            /* * CRITICAL FIX:
             * Glibc 2.32+ 默认使用 rseq (Restartable Sequences) 优化线程同步。
             * 宿主环境 (HarmonyOS) 的安全策略禁止此调用并发送 SIGSYS。
             * 解决方法：拦截并返回 -ENOSYS (Function not implemented)，
             * 迫使 Glibc 降级使用旧的锁机制。
             */
            DEBUG_LOG("[Payload] Mocking rseq -> -ENOSYS to prevent SIGSYS\n");
            ret = -38; /* -ENOSYS */
            break;

        /* Debugging Suspect Syscalls */
        case SYS_getrandom:
            DEBUG_LOG("[Payload] SYSCALL: getrandom (278) - Passing through...\n");
            ret = do_syscall(sys_no, args);
            break;

        case SYS_membarrier:
            DEBUG_LOG("[Payload] SYSCALL: membarrier (283) - Passing through...\n");
            ret = do_syscall(sys_no, args);
            break;

        case SYS_prctl:
            DEBUG_LOG("[Payload] SYSCALL: prctl (167) - Passing through...\n");
            ret = do_syscall(sys_no, args);
            break;
            
        case SYS_faccessat2:
            DEBUG_LOG("[Payload] SYSCALL: faccessat2 (439) - Passing through...\n");
            ret = do_syscall(sys_no, args);
            break;

        case SYS_statx:
            DEBUG_LOG("[Payload] SYSCALL: statx (291) - Passing through...\n");
            ret = do_syscall(sys_no, args);
            break;

        case SYS_statfs: {
            DEBUG_LOG("[Payload] statfs -> VFS\n");
            const char *virt_path = (const char *)args[0];
            if (virt_path) {
                vfs_path_result_t res = vfs_resolve(virt_path, sys_no, args);
                if (res.error) {
                    ret = res.error;
                    break;
                }
                log_path_pair("[Payload] statfs path ", virt_path, res.path);
                args[0] = (long)res.path;
            }
            ret = do_syscall(sys_no, args);
            break;
        }

        case SYS_fstatfs:
            log_errno_value("[Payload] fstatfs fd ", args[0]);
            ret = do_syscall(sys_no, args);
            break;

        case SYS_clone3:
            DEBUG_LOG("[Payload] Mocking clone3(435) -> -ENOSYS to force fallback to clone()\n");
            ret = -38; /* -ENOSYS */
            break;

        default:
            /* Passthrough */
            ret = do_syscall(sys_no, args);
            break;
    }

    syscall_common_scratch_free(scratch);
    return ret;
}
