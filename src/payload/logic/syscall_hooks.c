#include "syscall_hooks.h"
#include "mini_libc.h"
#include "config.h"
#include "execve_utils.h"
#include "path_rewrite.h"
#include "syscall_nums.h"
#include "hook_runtime.h"
#include "log.h"

#define AT_FDCWD        (-100)
#define AT_EMPTY_PATH   0x1000
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
#ifndef O_NOFOLLOW
#define O_NOFOLLOW      0x20000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef AT_SYMLINK_FOLLOW
#define AT_SYMLINK_FOLLOW 0x400
#endif
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
#ifndef SIGSEGV
#define SIGSEGV 11
#endif

#define DEBUG_LOG(msg) LOG_DEBUG(msg)

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);
unsigned long sys_strlen(const char *s);
extern payload_config_t g_payload_config;
extern void _start(void);

static int log_debug_enabled(void)
{
    return log_level_enabled(LOG_LEVEL_DEBUG);
}

static void log_path(const char *tag, const char *path)
{
    if (!log_debug_enabled() || !tag || !path)
        return;
    sys_write(2, tag, sys_strlen(tag));
    sys_write(2, path, sys_strlen(path));
    sys_write(2, "\n", 1);
}

static void log_path_pair(const char *tag, const char *p1, const char *p2)
{
    if (!log_debug_enabled() || !tag)
        return;
    sys_write(2, tag, sys_strlen(tag));
    if (p1) sys_write(2, p1, sys_strlen(p1));
    if (p2) {
        sys_write(2, " -> ", 4);
        sys_write(2, p2, sys_strlen(p2));
    }
    sys_write(2, "\n", 1);
}

static void format_int(long v, char *buf, size_t buf_sz);

static void log_errno_value(const char *tag, long err)
{
    if (!log_debug_enabled() || !tag)
        return;
    char buf[32];
    format_int(err, buf, sizeof(buf));
    sys_write(2, tag, sys_strlen(tag));
    sys_write(2, buf, sys_strlen(buf));
    sys_write(2, "\n", 1);
}

#define UTSNAME_LEN 65
struct utsname {
    char sysname[UTSNAME_LEN];
    char nodename[UTSNAME_LEN];
    char release[UTSNAME_LEN];
    char version[UTSNAME_LEN];
    char machine[UTSNAME_LEN];
    char domainname[UTSNAME_LEN];
};

static int sys_streq(const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    while (*a && *b) {
        if (*a != *b)
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int is_harmonyos(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;

    struct utsname u;
    long rc = raw_syscall(SYS_uname, (long)&u, 0, 0, 0, 0, 0);
    if (rc < 0) {
        cached = 0;
        return cached;
    }

    cached = sys_streq(u.sysname, "HarmonyOS") ? 1 : 0;
    return cached;
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

static void format_int(long v, char *buf, size_t buf_sz)
{
    if (!buf || buf_sz == 0)
        return;
    size_t pos = 0;
    int sign = 0;
    if (v < 0) {
        sign = 1;
        v = -v;
    }
    char rev[32];
    size_t rpos = 0;
    if (v == 0) {
        rev[rpos++] = '0';
    } else {
        while (v > 0 && rpos < sizeof(rev)) {
            rev[rpos++] = '0' + (v % 10);
            v /= 10;
        }
    }
    if (sign && rpos < sizeof(rev))
        rev[rpos++] = '-';
    while (rpos > 0 && pos + 1 < buf_sz)
        buf[pos++] = rev[--rpos];
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

static int resolve_symlink_target_at(long dirfd, const char *path,
                                     char *resolved, size_t resolved_sz)
{
    if (!path || !resolved || resolved_sz == 0)
        return 0;
    char linkbuf[CONFIG_MAX_PATH];
    long n = raw_syscall(SYS_readlinkat, dirfd, (long)path, (long)linkbuf, sizeof(linkbuf) - 1, 0, 0);
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

static int resolve_symlink_target(const char *path, char *resolved, size_t resolved_sz)
{
    return resolve_symlink_target_at(AT_FDCWD, path, resolved, resolved_sz);
}

struct symlink_chain_scratch {
    char current[CONFIG_MAX_PATH];
    char next[CONFIG_MAX_PATH];
};

static struct symlink_chain_scratch *symlink_chain_scratch_alloc(void)
{
    size_t sz = sizeof(struct symlink_chain_scratch);
    void *p = (void *)raw_syscall(SYS_mmap, 0, (long)sz,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((long)p < 0)
        return NULL;
    return (struct symlink_chain_scratch *)p;
}

static void symlink_chain_scratch_free(struct symlink_chain_scratch *scratch)
{
    if (!scratch)
        return;
    raw_syscall(SYS_munmap, (long)scratch, (long)sizeof(*scratch), 0, 0, 0, 0);
}

static int resolve_symlink_chain_at(long dirfd, const char *path, char *out, size_t out_sz)
{
    if (!path || !out || out_sz == 0)
        return 0;
    struct symlink_chain_scratch *scratch = symlink_chain_scratch_alloc();
    if (!scratch)
        return 0;
    safe_cpy(scratch->current, sizeof(scratch->current), path);

    int changed = 0;
    for (int depth = 0; depth < 4; depth++) {
        if (!resolve_symlink_target_at(dirfd, scratch->current,
                                       scratch->next, sizeof(scratch->next)))
            break;
        safe_cpy(scratch->current, sizeof(scratch->current), scratch->next);
        changed = 1;
    }
    if (!changed) {
        symlink_chain_scratch_free(scratch);
        return 0;
    }
    safe_cpy(out, out_sz, scratch->current);
    symlink_chain_scratch_free(scratch);
    return 1;
}

static int resolve_symlink_chain(const char *path, char *out, size_t out_sz)
{
    return resolve_symlink_chain_at(AT_FDCWD, path, out, out_sz);
}

static const char *rewrite_path_resolved(const char *orig, char *buf, size_t buf_sz)
{
    if (!orig)
        return orig;
    const char *rw = rewrite_path(orig, buf, buf_sz);
    char resolved[CONFIG_MAX_PATH];
    if (resolve_symlink_chain(rw, resolved, sizeof(resolved))) {
        safe_cpy(buf, buf_sz, resolved);
        rw = buf;
    }
    return rw;
}

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

static const char *path_basename(const char *path)
{
    if (!path)
        return NULL;
    const char *last = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' && p[1] != '\0')
            last = p + 1;
    }
    return last;
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

static int format_fd_path(char *out, size_t out_sz, int fd)
{
    if (!out || out_sz == 0 || fd < 0)
        return 0;
    const char *prefix = "/proc/self/fd/";
    size_t pos = 0;
    while (prefix[pos] && pos + 1 < out_sz) {
        out[pos] = prefix[pos];
        pos++;
    }
    if (pos + 2 >= out_sz)
        return 0;
    char numbuf[16];
    int npos = 0;
    if (fd == 0) {
        numbuf[npos++] = '0';
    } else {
        int tmp = fd;
        char rev[16];
        int rpos = 0;
        while (tmp > 0 && rpos < (int)sizeof(rev)) {
            rev[rpos++] = '0' + (tmp % 10);
            tmp /= 10;
        }
        while (rpos > 0)
            numbuf[npos++] = rev[--rpos];
    }
    if (pos + npos + 1 >= out_sz)
        return 0;
    for (int i = 0; i < npos; i++)
        out[pos++] = numbuf[i];
    out[pos] = '\0';
    return 1;
}

static long execveat_loader_fd(int fd, char **argv, char **envp)
{
    return raw_syscall(SYS_execveat, fd, (long)"", (long)argv,
                       (long)envp, AT_EMPTY_PATH, 0);
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

static long handle_execve_like(long sys_no, long *args, int is_execveat)
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
                const char *guest_path = rewrite_path_from_host(host_path,
                                                               scratch->out_path,
                                                               sizeof(scratch->out_path));
                size_t guest_len = sys_strlen(guest_path);
                if (guest_len + 1 <= (size_t)args[1]) {
                    small_copy((char *)args[0], guest_path);
                    ret = guest_len;
                }
            }
            break;

        case SYS_chdir:
            DEBUG_LOG("[Payload] chdir\n");
            if ((const char *)args[0]) {
                args[0] = (long)rewrite_path((const char *)args[0],
                                             scratch->new_path,
                                             sizeof(scratch->new_path));
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
            DEBUG_LOG("[Payload] fakeroot set* uid/gid -> fake 0\n");
            ret = 0;
            break;

        /* Fakeroot Phase2: 信息查询伪造 */
        case SYS_getuid:
        case SYS_geteuid:
        case SYS_getgid:
        case SYS_getegid:
            DEBUG_LOG("[Payload] fakeroot get[u/g]id -> 0\n");
            ret = 0;
            break;
        case SYS_getresuid: {
            DEBUG_LOG("[Payload] fakeroot getresuid\n");
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
            DEBUG_LOG("[Payload] fakeroot getresgid\n");
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
            DEBUG_LOG("[Payload] fakeroot getgroups\n");
            int size = (int)args[0];
            int *list = (int *)args[1];
            if (list && size > 0) {
                list[0] = 0; /* root group */
            }
            ret = (size > 0) ? 1 : 0;
            break;
        }

        case SYS_symlinkat: {
            /* symlinkat(target, newdirfd, linkpath) 参数顺序与 *at 系列不同 */
            if ((const char *)args[0]) {
                const char *orig_target = (const char *)args[0];
                const char *rw_target = rewrite_path(orig_target,
                                                     scratch->new_path,
                                                     sizeof(scratch->new_path));
                if (resolve_symlink_chain(rw_target,
                                          scratch->resolved_target,
                                          sizeof(scratch->resolved_target))) {
                    rw_target = scratch->resolved_target;
                }
                log_path_pair("[Payload] symlink target ", orig_target, rw_target);
                args[0] = (long)rw_target;
            }
            if ((const char *)args[2]) {
                const char *orig_link = (const char *)args[2];
                const char *rw_link = rewrite_path(orig_link,
                                                   scratch->new_path2,
                                                   sizeof(scratch->new_path2));
                if (resolve_symlink_chain(rw_link,
                                          scratch->resolved_link,
                                          sizeof(scratch->resolved_link))) {
                    rw_link = scratch->resolved_link;
                }
                log_path_pair("[Payload] path arg2 ", orig_link, rw_link);
                args[2] = (long)rw_link;
            }
            ret = do_syscall(sys_no, args);
            break;
        }

        case SYS_linkat: {
            /* 设备不支持硬链时退化为软链；源/目标仅做前缀重写，不解析 */
            const char *orig_old = (const char *)args[1];
            const char *orig_new = (const char *)args[3];
            if (orig_old) {
                const char *rw_old = rewrite_path(orig_old,
                                                  scratch->new_path,
                                                  sizeof(scratch->new_path));
                log_path_pair("[Payload] linkat old ", orig_old, rw_old);
                args[1] = (long)rw_old;
            }
            if (orig_new) {
                const char *rw_new = rewrite_path(orig_new,
                                                  scratch->new_path2,
                                                  sizeof(scratch->new_path2));
                log_path_pair("[Payload] linkat new ", orig_new, rw_new);
                args[3] = (long)rw_new;
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
        case SYS_newfstatat:
            if ((const char *)args[1]) {
                const char *orig = (const char *)args[1];
                const char *rw = rewrite_path(orig,
                                              scratch->new_path,
                                              sizeof(scratch->new_path));
                int need_resolve = 1;
                if (sys_no == SYS_unlinkat || sys_no == SYS_readlinkat || sys_no == SYS_renameat) {
                    need_resolve = 0;
                } else if (sys_no == SYS_openat) {
                    int flags = (int)args[2];
                    if (flags & O_NOFOLLOW)
                        need_resolve = 0;
                } else if (sys_no == SYS_newfstatat || sys_no == SYS_faccessat) {
                    int flags = (int)args[3];
                    if (flags & AT_SYMLINK_NOFOLLOW) {
                        need_resolve = 0;
                    }
                }
                if (need_resolve) {
                    if (resolve_symlink_chain(rw,
                                              scratch->resolved,
                                              sizeof(scratch->resolved))) {
                        rw = scratch->resolved;
                    }
                }
                log_path_pair("[Payload] path arg1 ", orig, rw);
                args[1] = (long)rw;
            }

            /* Only renameat reaches here; symlinkat has its own handler */
            if (sys_no == SYS_renameat) {
                if ((const char *)args[3]) {
                    const char *orig2 = (const char *)args[3];
                    const char *rw2 = rewrite_path(orig2,
                                                   scratch->new_path2,
                                                   sizeof(scratch->new_path2));
                    /* renameat/linkat 新路径不应跟随符号链接 */
                    log_path_pair("[Payload] path arg3 ", orig2, rw2);
                    args[3] = (long)rw2;
                }
            }
            if (sys_no == SYS_readlinkat && args[2]) {
                /* Use a bounce buffer so we can rewrite output path */
                char *user_buf = (char *)args[2];
                long user_len = args[3];
                long count = user_len;
                if (count > (long)sizeof(scratch->bounce))
                    count = sizeof(scratch->bounce);
                args[2] = (long)scratch->bounce;
                args[3] = count;
                ret = do_syscall(sys_no, args);
                if (ret > 0 && ret < count) {
                    scratch->bounce[ret] = '\0';
                    const char *guest_path = rewrite_path_from_host(scratch->bounce,
                                                                   scratch->new_path,
                                                                   sizeof(scratch->new_path));
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

        case SYS_fchmodat: {
            DEBUG_LOG("[Payload] fchmodat\n");
            if ((const char *)args[1]) {
                const char *orig = (const char *)args[1];
                const char *rw = rewrite_path(orig,
                                              scratch->new_path,
                                              sizeof(scratch->new_path));
                int flags = (int)args[3];
                if (!(flags & AT_SYMLINK_NOFOLLOW)) {
                    if (resolve_symlink_chain(rw,
                                              scratch->resolved,
                                              sizeof(scratch->resolved))) {
                        rw = scratch->resolved;
                    }
                }
                log_path_pair("[Payload] fchmodat path ", orig, rw);
                args[1] = (long)rw;
            }
            ret = 0;
            break;
        }

        case SYS_fchownat: {
            DEBUG_LOG("[Payload] fchownat\n");
            if ((const char *)args[1]) {
                const char *orig = (const char *)args[1];
                const char *rw = rewrite_path(orig,
                                              scratch->new_path,
                                              sizeof(scratch->new_path));
                int flags = (int)args[3];
                if (!(flags & AT_SYMLINK_NOFOLLOW)) {
                    if (resolve_symlink_chain(rw,
                                              scratch->resolved,
                                              sizeof(scratch->resolved))) {
                        rw = scratch->resolved;
                    }
                }
                log_path_pair("[Payload] fchownat path ", orig, rw);
                args[1] = (long)rw;
            }
            ret = 0;
            break;
        }

        case SYS_utimensat:
            DEBUG_LOG("[Payload] utimensat\n");
            if ((const char *)args[1]) {
                const char *orig = (const char *)args[1];
                const char *rw = rewrite_path(orig,
                                              scratch->new_path,
                                              sizeof(scratch->new_path));
                int flags = (int)args[3];
                if (!(flags & AT_SYMLINK_NOFOLLOW)) {
                    if (resolve_symlink_chain(rw,
                                              scratch->resolved,
                                              sizeof(scratch->resolved))) {
                        rw = scratch->resolved;
                    }
                }
                log_path_pair("[Payload] utimensat path ", orig, rw);
                args[1] = (long)rw;
            }
            ret = 0;
            break;

        case SYS_fchmod:
            DEBUG_LOG("[Payload] fchmod\n");
            ret = 0;
            break;

        case SYS_fchown:
            DEBUG_LOG("[Payload] fchown\n");
            ret = 0;
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
