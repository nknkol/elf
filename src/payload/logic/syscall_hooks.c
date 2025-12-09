#include "syscall_hooks.h"
#include "mini_libc.h"
#include "config.h"
#include "execve_utils.h"
#include "path_rewrite.h"
#include "syscall_nums.h"
#include "hook_runtime.h"

#define AT_FDCWD        (-100)
#define ENOENT          2

#define MAX_EXEC_ARGS   128
#define MAX_EXEC_ENVS   128

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
#define PR_JIT_WORKAROUND 0x6a6974
#ifndef O_RDONLY
#define O_RDONLY        0
#endif
#ifndef ELFMAG0
#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#endif

#define SAFE_LOG(msg) do { \
    if (config_log_enabled()) { \
        static const char _buf[] = msg; \
        sys_write(1, _buf, sizeof(_buf) - 1); \
    } \
} while (0)

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);
unsigned long sys_strlen(const char *s);
extern payload_config_t g_payload_config;
extern void _start(void);

static void log_path(const char *tag, const char *path)
{
    if (!config_log_enabled() || !tag || !path)
        return;
    sys_write(1, tag, sys_strlen(tag));
    sys_write(1, path, sys_strlen(path));
    sys_write(1, "\n", 1);
}

static void log_path_pair(const char *tag, const char *p1, const char *p2)
{
    if (!config_log_enabled() || !tag)
        return;
    sys_write(1, tag, sys_strlen(tag));
    if (p1) sys_write(1, p1, sys_strlen(p1));
    if (p2) {
        sys_write(1, " -> ", 4);
        sys_write(1, p2, sys_strlen(p2));
    }
    sys_write(1, "\n", 1);
}

static void small_copy(char *dst, const char *src)
{
    if (!dst || !src) return;
    while (*src) {
        *dst++ = *src++;
    }
    *dst = 0;
}

static void format_range(int min, int max, char *buf, size_t buf_sz)
{
    if (!buf || buf_sz == 0)
        return;
    size_t pos = 0;
    int vals[2] = { min, max };
    for (int idx = 0; idx < 2; idx++) {
        int v = vals[idx];
        char tmp[32];
        int tpos = 0;
        if (v == 0) {
            tmp[tpos++] = '0';
        } else {
            int sign = 0;
            if (v < 0) { sign = 1; v = -v; }
            char rev[32];
            int rpos = 0;
            while (v > 0 && rpos < (int)sizeof(rev)) {
                rev[rpos++] = '0' + (v % 10);
                v /= 10;
            }
            if (sign && rpos < (int)sizeof(rev))
                rev[rpos++] = '-';
            while (rpos > 0 && tpos + 1 < (int)sizeof(tmp))
                tmp[tpos++] = rev[--rpos];
        }
        for (int i = 0; i < tpos && pos + 1 < buf_sz; i++)
            buf[pos++] = tmp[i];
        if (idx == 0 && pos + 1 < buf_sz)
            buf[pos++] = '-';
    }
    buf[pos < buf_sz ? pos : buf_sz - 1] = '\0';
}

static int path_exists(const char *path)
{
    if (!path || !path[0])
        return 0;
    long r = raw_syscall(SYS_faccessat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    return r == 0;
}

static size_t dir_len(const char *path)
{
    size_t len = sys_strlen(path);
    while (len > 0 && path[len - 1] != '/')
        len--;
    return len ? len - (len == 1 ? 1 : 0) : 0;
}

static void join_paths(char *out, size_t out_sz,
                       const char *base, size_t base_len,
                       const char *suffix)
{
    size_t pos = 0;
    if (!out || out_sz == 0)
        return;

    for (; pos + 1 < out_sz && base && pos < base_len; pos++)
        out[pos] = base[pos];

    if (pos > 0 && out[pos - 1] != '/' && suffix && suffix[0] != '/') {
        if (pos + 1 < out_sz)
            out[pos++] = '/';
    } else if (pos > 0 && out[pos - 1] == '/' && suffix && suffix[0] == '/') {
        suffix++;
    }

    size_t i = 0;
    while (suffix && suffix[i] && pos + 1 < out_sz) {
        out[pos++] = suffix[i++];
    }
    out[pos] = '\0';
}

static int resolve_symlink_target(const char *path, char *resolved, size_t resolved_sz)
{
    if (!path || !resolved || resolved_sz == 0)
        return 0;
    char linkbuf[CONFIG_MAX_PATH];
    long n = raw_syscall(SYS_readlinkat, AT_FDCWD, (long)path, (long)linkbuf, sizeof(linkbuf) - 1, 0, 0);
    if (n < 0)
        return 0;
    if ((size_t)n >= sizeof(linkbuf))
        n = sizeof(linkbuf) - 1;
    linkbuf[n] = '\0';

    if (linkbuf[0] == '/') {
        rewrite_path(linkbuf, resolved, resolved_sz);
    } else {
        size_t prefix_len = dir_len(path);
        join_paths(resolved, resolved_sz, path, prefix_len, linkbuf);
    }
    return 1;
}

static int resolve_symlink_chain(const char *path, char *out, size_t out_sz)
{
    if (!path || !out || out_sz == 0)
        return 0;
    char current[CONFIG_MAX_PATH];
    safe_cpy(current, sizeof(current), path);

    int changed = 0;
    for (int depth = 0; depth < 4; depth++) {
        char next[CONFIG_MAX_PATH];
        if (!resolve_symlink_target(current, next, sizeof(next)))
            break;
        safe_cpy(current, sizeof(current), next);
        changed = 1;
    }
    if (!changed)
        return 0;
    safe_cpy(out, out_sz, current);
    return 1;
}

static int is_elf_file(const char *path)
{
    if (!path)
        return 0;
    long fd = raw_syscall(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
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

static int parse_shebang(const char *path, char *interp, size_t interp_sz,
                         char *arg, size_t arg_sz)
{
    if (!path || !interp || interp_sz == 0)
        return 0;
    if (arg && arg_sz)
        arg[0] = '\0';

    long fd = raw_syscall(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
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

static int find_loader_path(char *out, size_t out_sz)
{
    char guest_path[CONFIG_MAX_PATH];
    guest_path[0] = '/';
    safe_cpy(guest_path + 1, sizeof(guest_path) - 1, "elfloader");
    rewrite_path(guest_path, out, out_sz);
    if (path_exists(out))
        return 1;
    return 0;
}

static inline long do_syscall(long sys_no, long *a) {
    return raw_syscall(sys_no, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void zero_region(void *addr, unsigned long len)
{
    unsigned char *p = (unsigned char *)addr;
    for (unsigned long i = 0; i < len; i++)
        p[i] = 0;
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

    if (prot & PROT_EXEC)
        raw_syscall(SYS_prctl, PR_JIT_WORKAROUND, 0, 0, 0, 0, 0);
    long mp = raw_syscall(SYS_mprotect, (long)mapped, (long)len, prot, 0, 0, 0);
    if (prot & PROT_EXEC)
        raw_syscall(SYS_prctl, PR_JIT_WORKAROUND, 0, 1, 0, 0, 0);

    if (mp < 0) {
        raw_syscall(SYS_munmap, (long)mapped, (long)len, 0, 0, 0, 0);
        return mp;
    }

    if (prot & PROT_EXEC)
        install_hook(mapped, len, (void *)&_start, 0);

    return (long)mapped;
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

long syscall_handle_common(long sys_no, long args[6]) {
    long ret;
    char new_path[CONFIG_MAX_PATH];
    char new_path2[CONFIG_MAX_PATH];
    char out_path[CONFIG_MAX_PATH];

    switch (sys_no) {
        case SYS_getcwd:
            SAFE_LOG("[Payload] getcwd\n");
            ret = do_syscall(sys_no, args);
            if (ret > 0 && (const char *)args[0]) {
                const char *host_path = (const char *)args[0];
                const char *guest_path = rewrite_path_from_host(host_path, out_path, sizeof(out_path));
                size_t guest_len = sys_strlen(guest_path);
                if (guest_len + 1 <= (size_t)args[1]) {
                    small_copy((char *)args[0], guest_path);
                    ret = guest_len;
                }
            }
            break;

        case SYS_chdir:
            SAFE_LOG("[Payload] chdir\n");
            if ((const char *)args[0]) {
                args[0] = (long)rewrite_path((const char *)args[0], new_path, sizeof(new_path));
            }
            ret = do_syscall(sys_no, args);
            break;

        /* Fakeroot Phase1/2: 身份切换调用全部假成功 */
        case SYS_setuid:
        case SYS_setgid:
        case SYS_setreuid:
        case SYS_setregid:
        case SYS_setresuid:
        case SYS_setresgid:
        case SYS_setfsuid:
        case SYS_setfsgid:
        case SYS_setgroups:
            SAFE_LOG("[Payload] fakeroot set* uid/gid -> fake 0\n");
            ret = 0;
            break;

        /* Fakeroot Phase2: 信息查询伪造 */
        case SYS_getuid:
        case SYS_geteuid:
        case SYS_getgid:
        case SYS_getegid:
            SAFE_LOG("[Payload] fakeroot get[u/g]id -> 0\n");
            ret = 0;
            break;
        case SYS_getresuid: {
            SAFE_LOG("[Payload] fakeroot getresuid\n");
            int *ruid = (int *)args[0];
            int *euid = (int *)args[1];
            int *suid = (int *)args[2];
            if (ruid) *ruid = 0;
            if (euid) *euid = 0;
            if (suid) *suid = 0;
            ret = 0;
            break;
        }
        case SYS_getresgid: {
            SAFE_LOG("[Payload] fakeroot getresgid\n");
            int *rgid = (int *)args[0];
            int *egid = (int *)args[1];
            int *sgid = (int *)args[2];
            if (rgid) *rgid = 0;
            if (egid) *egid = 0;
            if (sgid) *sgid = 0;
            ret = 0;
            break;
        }
        case SYS_getgroups: {
            SAFE_LOG("[Payload] fakeroot getgroups\n");
            int size = (int)args[0];
            int *list = (int *)args[1];
            if (list && size > 0) {
                list[0] = 0; /* root group */
            }
            ret = (size > 0) ? 1 : 0;
            break;
        }

        case SYS_mkdirat:
        case SYS_mknodat:
        case SYS_unlinkat:
        case SYS_linkat:
        case SYS_renameat:
        case SYS_openat:
        case SYS_faccessat:
        case SYS_symlinkat:
        case SYS_readlinkat:
        case SYS_newfstatat:
            if ((const char *)args[1]) {
                const char *orig = (const char *)args[1];
                const char *rw = rewrite_path(orig, new_path, sizeof(new_path));
                char resolved[CONFIG_MAX_PATH];
                if (resolve_symlink_chain(rw, resolved, sizeof(resolved))) {
                    rw = resolved;
                }
                log_path_pair("[Payload] path arg1 ", orig, rw);
                args[1] = (long)rw;
            }

            if (sys_no == SYS_linkat || sys_no == SYS_renameat || sys_no == SYS_symlinkat) {
                if ((const char *)args[3]) {
                    const char *orig2 = (const char *)args[3];
                    const char *rw2 = rewrite_path(orig2, new_path2, sizeof(new_path2));
                    char resolved2[CONFIG_MAX_PATH];
                    if (resolve_symlink_chain(rw2, resolved2, sizeof(resolved2))) {
                        rw2 = resolved2;
                    }
                    log_path_pair("[Payload] path arg3 ", orig2, rw2);
                    args[3] = (long)rw2;
                }
            }
            if (sys_no == SYS_readlinkat && args[2]) {
                /* Use a bounce buffer so we can rewrite output path */
                char bounce[CONFIG_MAX_PATH];
                char *user_buf = (char *)args[2];
                long user_len = args[3];
                long count = user_len;
                if (count > (long)sizeof(bounce))
                    count = sizeof(bounce);
                args[2] = (long)bounce;
                args[3] = count;
                ret = do_syscall(sys_no, args);
                if (ret > 0 && ret < count) {
                    bounce[ret] = '\0';
                    const char *guest_path = rewrite_path_from_host(bounce, new_path, sizeof(new_path));
                    size_t guest_len = sys_strlen(guest_path);
                    if (guest_len < (size_t)user_len) {
                        small_copy(user_buf, guest_path);
                        ret = guest_len;
                    }
                }
                args[2] = (long)user_buf;
                args[3] = user_len;
            } else {
                ret = do_syscall(sys_no, args);
            }
            break;

        case SYS_execve:
            SAFE_LOG("[Payload] execve\n");
            if (!args[0]) {
                ret = do_syscall(sys_no, args);
                break;
            }

            {
                char argv_buf[MAX_EXEC_ARGS][CONFIG_MAX_PATH];
                char env_buf[MAX_EXEC_ENVS][CONFIG_MAX_PATH];
                char *argv_out[MAX_EXEC_ARGS];
                char *env_out[MAX_EXEC_ENVS];
                payload_config_t *cfg = &g_payload_config;
                const char *cfg_path = cfg->config_path[0] ? cfg->config_path : NULL;

                /* Build argv list with rewritten paths */
                if (!build_exec_vec((const char *const *)args[1], argv_out, argv_buf, MAX_EXEC_ARGS, 1)) {
                    ret = -ENOENT;
                    break;
                }

                /* Build env list with rewritten PATH/LD_LIBRARY_PATH/etc. */
                if (!build_exec_env((const char *const *)args[2], env_out, env_buf, MAX_EXEC_ENVS)) {
                    ret = -ENOENT;
                    break;
                }

                const char *orig_path = (const char *)args[0];
                char exec_path[CONFIG_MAX_PATH];
                rewrite_path(orig_path, exec_path, sizeof(exec_path));
                log_path_pair("[Payload] execve pathname ", orig_path, exec_path);

                char resolved[CONFIG_MAX_PATH];
                int is_link = resolve_symlink_chain(exec_path, resolved, sizeof(resolved));
                const char *target_path = is_link ? resolved : exec_path;
                log_path_pair("[Payload] execve target ", exec_path, target_path);
                const char *arg0_path = argv_out[0]; /* 原始 argv[0] 名字 */

                int elf = is_elf_file(target_path);
                log_path_pair("[Payload] execve elf? ", target_path, elf ? "yes" : "no");
                if (!elf) {
                    char sb_interp[CONFIG_MAX_PATH];
                    char sb_arg[CONFIG_MAX_PATH];
                    if (parse_shebang(target_path, sb_interp, sizeof(sb_interp),
                                      sb_arg, sizeof(sb_arg))) {
                        log_path("[Payload] execve shebang interp=", sb_interp);
                        if (sb_arg[0])
                            log_path("[Payload] execve shebang arg=", sb_arg);
                        char interp_full[CONFIG_MAX_PATH];
                        if (sb_interp[0] == '/') {
                            rewrite_path(sb_interp, interp_full, sizeof(interp_full));
                        } else {
                            size_t prefix_len = dir_len(target_path);
                            join_paths(interp_full, sizeof(interp_full),
                                       target_path, prefix_len, sb_interp);
                            rewrite_path(interp_full, interp_full, sizeof(interp_full));
                        }
                        log_path("[Payload] execve shebang interp rewritten=", interp_full);

                        SAFE_LOG("[Payload] execve shebang -> loader\n");
                        /* interpreter path will be argv_out[0] after loader insertion */
                        argv_out[0] = (char *)interp_full;

                        char loader_path[CONFIG_MAX_PATH];
                        if (!find_loader_path(loader_path, sizeof(loader_path))) {
                            SAFE_LOG("[Payload] loader not found\n");
                            ret = -ENOENT;
                            break;
                        }

                        int argc = 0;
                        while (argv_out[argc])
                            argc++;
                        int extra = 3 + (cfg_path ? 2 : 0); /* loader, child flag, script */
                        if (sb_arg[0])
                            extra++;
                        if (argc + extra + 1 >= MAX_EXEC_ARGS) {
                            ret = -ENOENT;
                            break;
                        }
                        for (int i = argc; i >= 1; i--) {
                            argv_out[i + extra - 1] = argv_out[i];
                        }

                        int pos = 0;
                        argv_out[pos++] = loader_path;
                        if (cfg_path) {
                            argv_out[pos++] = "-c";
                            argv_out[pos++] = (char *)cfg_path;
                        }
                        argv_out[pos++] = CONFIG_CHILD_LOADER_ARG;
                        /* interpreter (already rewritten) */
                        argv_out[pos++] = (char *)interp_full;
                        if (sb_arg[0])
                            argv_out[pos++] = sb_arg;
                        argv_out[pos++] = (char *)arg0_path; /* script 保留原始名/路径 */
                        argv_out[argc + extra] = NULL;

                        args[0] = (long)loader_path;
                        args[1] = (long)argv_out;
                        args[2] = (long)env_out;

                        ret = do_syscall(sys_no, args);
                        break;
                    } else {
                        SAFE_LOG("[Payload] execve passthrough (non-elf, no shebang)\n");
                        argv_out[0] = (char *)target_path;
                        args[0] = (long)target_path;
                        args[1] = (long)argv_out;
                        args[2] = (long)env_out;
                        ret = do_syscall(sys_no, args);
                        break;
                    }
                }
                /* 错误写法: argv_out[0] = (char *)arg0_path; */
                /* 正确写法: 使用原始虚拟路径 (如 /bin/ls) */
                SAFE_LOG("[Payload] execve chain loader (elf)\n");
                argv_out[0] = (char *)orig_path;

                /* Resolve loader path */
                char loader_path[CONFIG_MAX_PATH];
                if (!find_loader_path(loader_path, sizeof(loader_path))) {
                    SAFE_LOG("[Payload] loader not found\n");
                    ret = -ENOENT;
                    break;
                }

                /* Shift argv right by 2 to insert loader + child flag */
                int argc = 0;
                while (argv_out[argc])
                    argc++;
                int extra = 2 + (cfg_path ? 2 : 0);
                if (g_payload_config.hook_range_set)
                    extra += 2;
                if (g_payload_config.hook_range_interp_set)
                    extra += 2;
                if (argc + extra + 1 >= MAX_EXEC_ARGS) {
                    ret = -ENOENT;
                    break;
                }
                for (int i = argc; i >= 0; i--) {
                    argv_out[i + extra] = argv_out[i];
                }
                int pos = 0;
                argv_out[pos++] = loader_path;
                if (cfg_path) {
                    argv_out[pos++] = "-c";
                    argv_out[pos++] = (char *)cfg_path;
                }
                argv_out[pos++] = CONFIG_CHILD_LOADER_ARG;
                if (g_payload_config.hook_range_set) {
                    argv_out[pos++] = "--hook-range";
                    static char hook_buf[32];
                    format_range(g_payload_config.hook_min,
                                 g_payload_config.hook_max,
                                 hook_buf, sizeof(hook_buf));
                    argv_out[pos++] = hook_buf;
                }
                if (g_payload_config.hook_range_interp_set) {
                    argv_out[pos++] = "--hook-range-interp";
                    static char hook_buf2[32];
                    format_range(g_payload_config.hook_min_interp,
                                 g_payload_config.hook_max_interp,
                                 hook_buf2, sizeof(hook_buf2));
                    argv_out[pos++] = hook_buf2;
                }
                argv_out[argc + extra] = NULL;

                args[0] = (long)loader_path;
                args[1] = (long)argv_out;
                args[2] = (long)env_out;

                ret = do_syscall(sys_no, args);
            }
            break;

        case SYS_exit:
        case SYS_exit_group:
            /* Fast path out */
            ret = do_syscall(sys_no, args);
            break;

        case SYS_mprotect:
            SAFE_LOG("[Payload] mprotect\n");
            if (args[2] & PROT_EXEC)
                raw_syscall(SYS_prctl, PR_JIT_WORKAROUND, 0, 0, 0, 0, 0);
            ret = do_syscall(sys_no, args);
            if (args[2] & PROT_EXEC)
                raw_syscall(SYS_prctl, PR_JIT_WORKAROUND, 0, 1, 0, 0, 0);
            if (ret == 0 && (args[2] & PROT_EXEC)) {
                install_hook((void *)args[0], (size_t)args[1], (void *)&_start, 0);
            }
            break;

        case SYS_mmap:
            SAFE_LOG("[Payload] mmap\n");
            if ((args[2] & PROT_EXEC) && !(args[3] & MAP_ANON) && (int)args[4] > 0) {
                ret = mmap_exec_anon_fallback(args);
            } else {
                ret = do_syscall(sys_no, args);
                if (ret >= 0 && (args[2] & PROT_EXEC)) {
                    install_hook((void *)ret, (size_t)args[1], (void *)&_start, 0);
                }
            }
            break;

        default:
            /* Passthrough */
            ret = do_syscall(sys_no, args);
            break;
    }

    return ret;
}
