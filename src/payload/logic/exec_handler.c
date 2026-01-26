#include "exec_handler.h"
#include "mini_libc.h"
#include "config.h"
#include "execve_utils.h"
#include "path_rewrite.h"
#include "syscall_nums.h"
#include "log.h"
#include "utils.h"
#include "vfs_core.h"

#define AT_FDCWD        (-100)
#define AT_EMPTY_PATH   0x1000
#define ENOENT          2

#define MAX_EXEC_ARGS   128
#define MAX_EXEC_ENVS   128

#define PROT_READ       0x1
#define PROT_WRITE      0x2
#define MAP_PRIVATE     0x02
#define MAP_ANON        0x20
#define MAP_ANONYMOUS   MAP_ANON
#define SYS_munmap      215

#ifndef EPERM
#define EPERM           1
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
#ifndef EOPNOTSUPP
#define EOPNOTSUPP      95
#endif
#ifndef O_RDONLY
#define O_RDONLY        0
#endif
#ifndef ELFMAG0
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#endif

#define DEBUG_LOG(msg) LOG_DEBUG(msg)

extern long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);
extern payload_config_t g_payload_config;

static int build_exec_vec(const char *const *in, char **out,
                          char buf[][CONFIG_MAX_PATH], size_t max_items,
                          int rewrite_paths);

static int is_elf_file_at(long dirfd, const char *path)
{
    if (!path)
        return 0;
    long fd = raw_syscall(SYS_openat, dirfd, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0)
        return 0;
    unsigned char magic[4];
    long r = raw_syscall(SYS_read, fd, (long)magic, sizeof(magic), 0, 0, 0);
    raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    if (r != (long)sizeof(magic))
        return 0;
    return magic[0] == ELFMAG0 && magic[1] == ELFMAG1 &&
           magic[2] == ELFMAG2 && magic[3] == ELFMAG3;
}

static int parse_shebang_at(long dirfd, const char *path, char *interp, size_t interp_sz,
                            char *arg, size_t arg_sz)
{
    if (!path || !interp || interp_sz == 0)
        return 0;
    if (arg && arg_sz)
        arg[0] = '\0';

    long fd = raw_syscall(SYS_openat, dirfd, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0)
        return 0;

    char buf[256];
    long n = raw_syscall(SYS_read, fd, (long)buf, sizeof(buf), 0, 0, 0);
    raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    if (n < 2 || buf[0] != '#' || buf[1] != '!')
        return 0;

    size_t pos = 2;
    while (pos < (size_t)n && (buf[pos] == ' ' || buf[pos] == '\t'))
        pos++;

    size_t out = 0;
    while (pos < (size_t)n && buf[pos] != '\n' && buf[pos] != '\r' &&
           buf[pos] != ' ' && buf[pos] != '\t') {
        if (out + 1 < interp_sz)
            interp[out++] = buf[pos];
        pos++;
    }
    interp[out] = '\0';
    if (out == 0)
        return 0;

    while (pos < (size_t)n && (buf[pos] == ' ' || buf[pos] == '\t'))
        pos++;

    out = 0;
    while (pos < (size_t)n && buf[pos] != '\n' && buf[pos] != '\r') {
        if (arg && out + 1 < arg_sz)
            arg[out] = buf[pos];
        pos++;
        out++;
    }
    if (arg && arg_sz)
        arg[(out + 1 < arg_sz) ? out : arg_sz - 1] = '\0';

    return 1;
}

struct k_stat {
    unsigned long st_dev;
    unsigned long st_ino;
    unsigned long st_nlink;
    unsigned int st_mode;
    unsigned int st_uid;
    unsigned int st_gid;
    unsigned int __pad0;
    unsigned long st_rdev;
    long st_size;
    long st_blksize;
    long st_blocks;
    long st_atime;
    unsigned long st_atime_nsec;
    long st_mtime;
    unsigned long st_mtime_nsec;
    long st_ctime;
    unsigned long st_ctime_nsec;
    long __unused[3];
};

static int stat_dev_ino_at(long dirfd, const char *path,
                           unsigned long *dev_out, unsigned long *ino_out)
{
    if (!path || !dev_out || !ino_out)
        return 0;
    struct k_stat st;
    long rc = raw_syscall(SYS_newfstatat, dirfd, (long)path, (long)&st, 0, 0, 0);
    if (rc < 0)
        return 0;
    *dev_out = st.st_dev;
    *ino_out = st.st_ino;
    return 1;
}

static const char *find_loader_path(char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
        return NULL;
    const char *val = g_payload_config.loader_path;
    if (val && val[0]) {
        safe_cpy(out, out_sz, val);
        return out;
    }
    return NULL;
}

static long execveat_loader_fd(int fd, char **argv, char **envp)
{
    return raw_syscall(SYS_execveat, fd, (long)"", (long)argv,
                       (long)envp, AT_EMPTY_PATH, 0);
}

static inline long do_syscall(long sys_no, long *a) {
    return raw_syscall(sys_no, a[0], a[1], a[2], a[3], a[4], a[5]);
}

struct execve_scratch {
    char argv_buf[MAX_EXEC_ARGS][CONFIG_MAX_PATH];
    char env_buf[MAX_EXEC_ENVS][CONFIG_MAX_PATH];
    char *argv_out[MAX_EXEC_ARGS];
    char *env_out[MAX_EXEC_ENVS];
    char exec_path_arg[CONFIG_MAX_PATH];
    char exec_path[CONFIG_MAX_PATH];
    char resolved[CONFIG_MAX_PATH];
    char sb_interp[CONFIG_MAX_PATH];
    char sb_arg[CONFIG_MAX_PATH];
    char interp_full[CONFIG_MAX_PATH];
    char loader_path[CONFIG_MAX_PATH];
    char dirfd_buf[32];
    char flags_buf[32];
    char hook_buf[32];
    char hook_buf2[32];
    char *orig_args[MAX_EXEC_ARGS];
};

static struct execve_scratch *execve_scratch_alloc(void)
{
    size_t sz = sizeof(struct execve_scratch);
    void *p = (void *)raw_syscall(SYS_mmap, 0, (long)sz,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)p < 0)
        return NULL;
    return (struct execve_scratch *)p;
}

static void execve_scratch_free(struct execve_scratch *scratch)
{
    if (!scratch)
        return;
    raw_syscall(SYS_munmap, (long)scratch, (long)sizeof(*scratch), 0, 0, 0, 0);
}

long handle_execve_like(long sys_no, long *args, int is_execveat)
{
    int path_idx = is_execveat ? 1 : 0;
    int argv_idx = is_execveat ? 2 : 1;
    int env_idx = is_execveat ? 3 : 2;
    int flags_idx = is_execveat ? 4 : -1;
    long dirfd = is_execveat ? args[0] : AT_FDCWD;
    int flags = (flags_idx >= 0) ? (int)args[flags_idx] : 0;

    if (is_execveat) {
        DEBUG_LOG("[Payload] execveat\n");
    } else {
        DEBUG_LOG("[Payload] execve\n");
    }

    const char *orig_path = (const char *)args[path_idx];
    if (!orig_path)
        return do_syscall(sys_no, args);
    if (is_execveat && orig_path[0] == '\0' && (flags & AT_EMPTY_PATH))
        return do_syscall(sys_no, args);

    struct execve_scratch *scratch = execve_scratch_alloc();
    if (!scratch)
        return -ENOMEM;
    char **argv_out = scratch->argv_out;
    char **env_out = scratch->env_out;
    payload_config_t *cfg = &g_payload_config;
    const char *cfg_path = cfg->config_path[0] ? cfg->config_path : NULL;
    long ret = -ENOENT;

    /* Build argv list with rewritten paths */
    if (!build_exec_vec((const char *const *)args[argv_idx], argv_out,
                        scratch->argv_buf, MAX_EXEC_ARGS, 0))
        goto out;

    /* Build env list with rewritten PATH/LD_LIBRARY_PATH/etc. */
    if (!build_exec_env((const char *const *)args[env_idx], env_out,
                        scratch->env_buf, MAX_EXEC_ENVS))
        goto out;
    int loader_fd = cfg->loader_fd;
    int have_loader_fd = loader_fd >= 0;
    const char *loader_path_env = find_loader_path(scratch->loader_path,
                                                   sizeof(scratch->loader_path));
    int norecurse = cfg->loader_norecurse;
    unsigned long loader_dev = (unsigned long)cfg->loader_dev;
    unsigned long loader_ino = (unsigned long)cfg->loader_ino;
    int have_loader_devino = (loader_dev != 0 && loader_ino != 0);

    safe_cpy(scratch->exec_path_arg, sizeof(scratch->exec_path_arg), orig_path);
    rewrite_path(orig_path, scratch->exec_path, sizeof(scratch->exec_path));
    log_path_pair(is_execveat ? "[Payload] execveat pathname " : "[Payload] execve pathname ",
                  orig_path, scratch->exec_path);

    long path_dirfd = dirfd;
    int is_link = resolve_symlink_chain_at(path_dirfd, scratch->exec_path,
                                           scratch->resolved, sizeof(scratch->resolved));
    const char *target_path = is_link ? scratch->resolved : scratch->exec_path;
    log_path_pair(is_execveat ? "[Payload] execveat target " : "[Payload] execve target ",
                  scratch->exec_path, target_path);
    const char *arg0_path = argv_out[0]; /* 原始 argv[0] 名字 */
    format_int(path_dirfd, scratch->dirfd_buf, sizeof(scratch->dirfd_buf));
    format_int(flags, scratch->flags_buf, sizeof(scratch->flags_buf));

    if (norecurse) {
        int is_loader = 0;
        if (have_loader_devino) {
            unsigned long dev = 0, ino = 0;
            if (stat_dev_ino_at(path_dirfd, target_path, &dev, &ino)) {
                if (dev == loader_dev && ino == loader_ino)
                    is_loader = 1;
            }
        }
        if (!is_loader) {
            const char *base = path_basename(target_path);
            if ((loader_path_env && sys_streq(target_path, loader_path_env)) ||
                (base && sys_streq(base, "elfloader"))) {
                is_loader = 1;
            }
        }
        if (is_loader) {
            DEBUG_LOG("[Payload] block recursive elfloader exec\n");
            ret = -EPERM;
            goto out;
        }
    }

    if (loader_path_env && sys_streq(target_path, loader_path_env)) {
        DEBUG_LOG("[Payload] execve target is loader, passthrough\n");
        argv_out[0] = (char *)target_path;
        if (is_execveat) {
            args[0] = dirfd;
            if (flags_idx >= 0)
                args[flags_idx] = flags;
        }
        args[path_idx] = (long)target_path;
        args[argv_idx] = (long)argv_out;
        args[env_idx] = (long)env_out;
        ret = do_syscall(sys_no, args);
        goto out;
    }

    int elf = is_elf_file_at(path_dirfd, target_path);
    log_path_pair(is_execveat ? "[Payload] execveat elf? " : "[Payload] execve elf? ",
                  target_path, elf ? "yes" : "no");
    if (!elf) {
        if (parse_shebang_at(path_dirfd, target_path,
                             scratch->sb_interp, sizeof(scratch->sb_interp),
                             scratch->sb_arg, sizeof(scratch->sb_arg))) {
            log_path(is_execveat ? "[Payload] execveat shebang interp=" : "[Payload] execve shebang interp=",
                     scratch->sb_interp);
            if (scratch->sb_arg[0])
                log_path(is_execveat ? "[Payload] execveat shebang arg=" : "[Payload] execve shebang arg=",
                         scratch->sb_arg);
            if (scratch->sb_interp[0] == '/') {
                rewrite_path(scratch->sb_interp, scratch->interp_full,
                             sizeof(scratch->interp_full));
            } else {
                size_t prefix_len = dir_len(target_path);
                join_paths(scratch->interp_full, sizeof(scratch->interp_full),
                           target_path, prefix_len, scratch->sb_interp);
                rewrite_path(scratch->interp_full, scratch->interp_full,
                             sizeof(scratch->interp_full));
            }
            log_path(is_execveat ? "[Payload] execveat shebang interp rewritten=" : "[Payload] execve shebang interp rewritten=", scratch->interp_full);

            if (is_execveat) {
                DEBUG_LOG("[Payload] execveat shebang -> loader\n");
            } else {
                DEBUG_LOG("[Payload] execve shebang -> loader\n");
            }
            argv_out[0] = (char *)scratch->interp_full;
            if (!have_loader_fd && !loader_path_env) {
                DEBUG_LOG("[Payload] loader fd/path missing\n");
                ret = -ENOENT;
                goto out;
            }
            if (loader_path_env && loader_path_env[0]) {
                safe_cpy(scratch->loader_path, sizeof(scratch->loader_path), loader_path_env);
                log_path("[Payload] loader path=", scratch->loader_path);
            } else {
                safe_cpy(scratch->loader_path, sizeof(scratch->loader_path), "/elfloader");
            }

            int orig_argc = 0;
            while (argv_out[orig_argc])
                orig_argc++;
            int option_slots = 1; /* loader_path */
            if (cfg_path)
                option_slots += 2; /* -c <cfg> */
            option_slots += 1; /* --child-loader */
            option_slots += 8; /* --exec-* options */
            if (g_payload_config.hook_range_set)
                option_slots += 2;
            if (g_payload_config.hook_range_interp_set)
                option_slots += 2;
            int additional_user = 1; /* script path */
            if (scratch->sb_arg[0])
                additional_user++;
            int total_needed = option_slots + orig_argc + additional_user;
            if (total_needed + 1 >= MAX_EXEC_ARGS)
                goto out;

            for (int i = 0; i <= orig_argc && i < MAX_EXEC_ARGS; i++)
                scratch->orig_args[i] = argv_out[i];
            int pos = 0;
            argv_out[pos++] = scratch->loader_path;
            if (cfg_path) {
                argv_out[pos++] = "-c";
                argv_out[pos++] = (char *)cfg_path;
            }
            argv_out[pos++] = CONFIG_CHILD_LOADER_ARG;
            argv_out[pos++] = CONFIG_CHILD_EXEC_TARGET;
            argv_out[pos++] = (char *)scratch->interp_full;
            argv_out[pos++] = CONFIG_CHILD_EXEC_PATH;
            argv_out[pos++] = scratch->exec_path_arg;
            argv_out[pos++] = CONFIG_CHILD_EXEC_DIRFD;
            argv_out[pos++] = scratch->dirfd_buf;
            argv_out[pos++] = CONFIG_CHILD_EXEC_FLAGS;
            argv_out[pos++] = scratch->flags_buf;
            if (g_payload_config.hook_range_set) {
                argv_out[pos++] = "--hook-range";
                format_range(g_payload_config.hook_min,
                             g_payload_config.hook_max,
                             scratch->hook_buf, sizeof(scratch->hook_buf));
                argv_out[pos++] = scratch->hook_buf;
            }
            if (g_payload_config.hook_range_interp_set) {
                argv_out[pos++] = "--hook-range-interp";
                format_range(g_payload_config.hook_min_interp,
                             g_payload_config.hook_max_interp,
                             scratch->hook_buf2, sizeof(scratch->hook_buf2));
                argv_out[pos++] = scratch->hook_buf2;
            }
            argv_out[pos++] = (char *)scratch->interp_full;
            if (scratch->sb_arg[0])
                argv_out[pos++] = scratch->sb_arg;
            argv_out[pos++] = (char *)arg0_path;
            for (int i = 1; i < orig_argc && pos < MAX_EXEC_ARGS - 1; i++)
                argv_out[pos++] = scratch->orig_args[i];
            argv_out[pos] = NULL;
            if (have_loader_fd) {
                DEBUG_LOG("[Payload] execve chain loader via fd\n");
                ret = execveat_loader_fd(loader_fd, argv_out, env_out);
                if (ret < 0) {
                    long err = -ret;
                    log_errno_value("[Payload] execveat fd failed errno=", err);
                    if (loader_path_env && loader_path_env[0]) {
                        argv_out[0] = scratch->loader_path;
                        DEBUG_LOG("[Payload] execve loader path\n");
                        ret = raw_syscall(SYS_execve, (long)scratch->loader_path,
                                          (long)argv_out, (long)env_out, 0, 0, 0);
                        if (ret < 0)
                            log_errno_value("[Payload] execve loader path errno=", -ret);
                    } else if (err == ENOSYS || err == EINVAL || err == EOPNOTSUPP ||
                               err == EACCES || err == EPERM || err == ENOENT) {
                        if (format_fd_path(scratch->loader_path,
                                           sizeof(scratch->loader_path),
                                           loader_fd)) {
                            argv_out[0] = scratch->loader_path;
                            log_path("[Payload] execve fd fallback path=", scratch->loader_path);
                            DEBUG_LOG("[Payload] execve fd fallback via /proc/self/fd\n");
                            ret = raw_syscall(SYS_execve, (long)scratch->loader_path,
                                              (long)argv_out, (long)env_out, 0, 0, 0);
                            if (ret < 0)
                                log_errno_value("[Payload] execve fd fallback errno=", -ret);
                        }
                    }
                }
            } else if (loader_path_env && loader_path_env[0]) {
                DEBUG_LOG("[Payload] execve loader path\n");
                ret = raw_syscall(SYS_execve, (long)scratch->loader_path,
                                  (long)argv_out, (long)env_out, 0, 0, 0);
                if (ret < 0)
                    log_errno_value("[Payload] execve loader path errno=", -ret);
            }
            goto out;
        } else {
            if (is_execveat) {
                DEBUG_LOG("[Payload] execveat passthrough (non-elf, no shebang)\n");
            } else {
                DEBUG_LOG("[Payload] execve passthrough (non-elf, no shebang)\n");
            }
            argv_out[0] = (char *)target_path;
            if (is_execveat) {
                args[0] = dirfd;
                if (flags_idx >= 0)
                    args[flags_idx] = flags;
            }
            args[path_idx] = (long)target_path;
            args[argv_idx] = (long)argv_out;
            args[env_idx] = (long)env_out;
            ret = do_syscall(sys_no, args);
            goto out;
        }
    }

    if (is_execveat) {
        DEBUG_LOG("[Payload] execveat chain loader (elf)\n");
    } else {
        DEBUG_LOG("[Payload] execve chain loader (elf)\n");
    }

    if (!have_loader_fd && !loader_path_env) {
        DEBUG_LOG("[Payload] loader fd/path missing\n");
        ret = -ENOENT;
        goto out;
    }
    if (loader_path_env && loader_path_env[0]) {
        safe_cpy(scratch->loader_path, sizeof(scratch->loader_path), loader_path_env);
        log_path("[Payload] loader path=", scratch->loader_path);
    } else {
        safe_cpy(scratch->loader_path, sizeof(scratch->loader_path), "/elfloader");
    }

    int argc = 0;
    while (argv_out[argc])
        argc++;
    int extra = 2 + (cfg_path ? 2 : 0);
    extra += 8; /* --exec-* options (key + value x4) */
    if (g_payload_config.hook_range_set)
        extra += 2;
    if (g_payload_config.hook_range_interp_set)
        extra += 2;
    if (argc + extra + 1 >= MAX_EXEC_ARGS)
        goto out;

    for (int i = argc; i >= 0; i--)
        argv_out[i + extra] = argv_out[i];

    int pos = 0;
    argv_out[pos++] = scratch->loader_path;
    if (cfg_path) {
        argv_out[pos++] = "-c";
        argv_out[pos++] = (char *)cfg_path;
    }
    argv_out[pos++] = CONFIG_CHILD_LOADER_ARG;
    argv_out[pos++] = CONFIG_CHILD_EXEC_TARGET;
    argv_out[pos++] = (char *)target_path;
    argv_out[pos++] = CONFIG_CHILD_EXEC_PATH;
    argv_out[pos++] = scratch->exec_path_arg;
    argv_out[pos++] = CONFIG_CHILD_EXEC_DIRFD;
    argv_out[pos++] = scratch->dirfd_buf;
    argv_out[pos++] = CONFIG_CHILD_EXEC_FLAGS;
    argv_out[pos++] = scratch->flags_buf;
    if (g_payload_config.hook_range_set) {
        argv_out[pos++] = "--hook-range";
        format_range(g_payload_config.hook_min,
                     g_payload_config.hook_max,
                     scratch->hook_buf, sizeof(scratch->hook_buf));
        argv_out[pos++] = scratch->hook_buf;
    }
    if (g_payload_config.hook_range_interp_set) {
        argv_out[pos++] = "--hook-range-interp";
        format_range(g_payload_config.hook_min_interp,
                     g_payload_config.hook_max_interp,
                     scratch->hook_buf2, sizeof(scratch->hook_buf2));
        argv_out[pos++] = scratch->hook_buf2;
    }
    argv_out[argc + extra] = NULL;

    if (have_loader_fd) {
        DEBUG_LOG("[Payload] execve chain loader via fd\n");
        ret = execveat_loader_fd(loader_fd, argv_out, env_out);
        if (ret < 0) {
            long err = -ret;
            log_errno_value("[Payload] execveat fd failed errno=", err);
            if (loader_path_env && loader_path_env[0]) {
                argv_out[0] = scratch->loader_path;
                DEBUG_LOG("[Payload] execve loader path\n");
                ret = raw_syscall(SYS_execve, (long)scratch->loader_path,
                                  (long)argv_out, (long)env_out, 0, 0, 0);
                if (ret < 0)
                    log_errno_value("[Payload] execve loader path errno=", -ret);
            } else if (err == ENOSYS || err == EINVAL || err == EOPNOTSUPP ||
                       err == EACCES || err == EPERM || err == ENOENT) {
                if (format_fd_path(scratch->loader_path,
                                   sizeof(scratch->loader_path),
                                   loader_fd)) {
                    argv_out[0] = scratch->loader_path;
                    log_path("[Payload] execve fd fallback path=", scratch->loader_path);
                    DEBUG_LOG("[Payload] execve fd fallback via /proc/self/fd\n");
                    ret = raw_syscall(SYS_execve, (long)scratch->loader_path,
                                      (long)argv_out, (long)env_out, 0, 0, 0);
                    if (ret < 0)
                        log_errno_value("[Payload] execve fd fallback errno=", -ret);
                }
            }
        }
    } else if (loader_path_env && loader_path_env[0]) {
        DEBUG_LOG("[Payload] execve loader path\n");
        ret = raw_syscall(SYS_execve, (long)scratch->loader_path,
                          (long)argv_out, (long)env_out, 0, 0, 0);
        if (ret < 0)
            log_errno_value("[Payload] execve loader path errno=", -ret);
    }

out:
    execve_scratch_free(scratch);
    return ret;
}

static int build_exec_vec(const char *const *in, char **out,
                          char buf[][CONFIG_MAX_PATH], size_t max_items,
                          int rewrite_paths)
{
    if (!out)
        return 0;
    size_t idx = 0;
    for (; idx + 1 < max_items; idx++) {
        const char *s = in ? in[idx] : NULL;
        if (!s)
            break;
        if (rewrite_paths) {
            rewrite_path(s, buf[idx], sizeof(buf[idx]));
        } else {
            safe_cpy(buf[idx], sizeof(buf[idx]), s);
        }
        out[idx] = buf[idx];
    }
    out[idx] = NULL;
    /* Overflow detection: if input still has entries, fail */
    if (in && idx + 1 == max_items && in[idx])
        return 0;
    return 1;
}
