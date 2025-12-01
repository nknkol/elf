#include "mini_libc.h"
#include "config.h"
#include "execve_utils.h"
#include "path_rewrite.h"

/* Syscall Numbers */
#define SYS_getcwd      17
#define SYS_mknodat     33
#define SYS_mkdirat     34
#define SYS_unlinkat    35
#define SYS_linkat      37
#define SYS_renameat    38
#define SYS_faccessat   48
#define SYS_chdir       49
#define SYS_openat      56
#define SYS_close       57
#define SYS_read        63
#define SYS_write       64
#define SYS_symlinkat   36
#define SYS_readlinkat  78
#define SYS_newfstatat  79
#define SYS_exit        93
#define SYS_exit_group  94
#define SYS_rt_sigreturn 139
#define SYS_execve      221
#define SYS_mprotect    226

#define AT_FDCWD        (-100)
#define ENOENT          2

#define MAX_EXEC_ARGS   128
#define MAX_EXEC_ENVS   128

#define SAFE_LOG(msg) do { \
    if (config_log_enabled()) { \
        static const char _buf[] = msg; \
        sys_write(1, _buf, sizeof(_buf) - 1); \
    } \
} while (0)

typedef struct {
    unsigned long regs[30]; // x0 - x29
    unsigned long lr;       // x30
    unsigned long _pad;
} pt_regs;

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);
unsigned long sys_strlen(const char *s);
extern payload_config_t g_payload_config;

static void small_copy(char *dst, const char *src)
{
    if (!dst || !src) return;
    while (*src) {
        *dst++ = *src++;
    }
    *dst = 0;
}

static void log_hex_safe(unsigned long val) {
    char buf[19];
    char map[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    
    buf[0] = '0'; buf[1] = 'x';
    for(int i = 0; i < 16; i++) {
        buf[17 - i] = map[val & 0xf];
        val >>= 4;
    }
    buf[18] = 0; // Null terminator? No, we use count 18.
    sys_write(1, buf, 18);
}

static void log_cstr(const char *prefix, const char *s)
{
    if (!config_log_enabled())
        return;
    if (prefix)
        sys_write(1, prefix, sys_strlen(prefix));
    if (s) {
        sys_write(1, s, sys_strlen(s));
    } else {
        static const char null_msg[] = "(null)";
        sys_write(1, null_msg, sizeof(null_msg) - 1);
    }
    sys_write(1, "\n", 1);
}

static int path_exists(const char *path)
{
    if (!path || !path[0])
        return 0;
    long r = raw_syscall(SYS_faccessat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    return r == 0;
}

static int join_dir_file(const char *dir, const char *file, char *out, size_t out_sz)
{
    if (!out || out_sz == 0 || !file)
        return 0;
    size_t pos = 0;
    if (dir) {
        size_t i = 0;
        while (dir[i] && pos + 1 < out_sz) {
            out[pos++] = dir[i++];
        }
    }
    if (pos > 0 && out[pos - 1] != '/') {
        if (pos + 1 < out_sz)
            out[pos++] = '/';
    }
    size_t i = 0;
    while (file[i] && pos + 1 < out_sz) {
        out[pos++] = file[i++];
    }
    out[pos] = '\0';
    return (pos + 1 < out_sz) ? 1 : 0;
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

long syscall_dispatcher(long sys_no, pt_regs *regs) {
    long ret;
    long *a = (long *)regs->regs;
    char new_path[CONFIG_MAX_PATH];
    char new_path2[CONFIG_MAX_PATH];
    char out_path[CONFIG_MAX_PATH];
    char cfg_path[CONFIG_MAX_PATH];
    long args[6];

    /* Copy original args to a scratch array so we don't mutate saved regs */
    args[0] = a[0];
    args[1] = a[1];
    args[2] = a[2];
    args[3] = a[3];
    args[4] = a[4];
    args[5] = a[5];

    /* Special case: infinite loop prevention */
    if (sys_no == SYS_write) {
        return raw_syscall(sys_no, a[0], a[1], a[2], a[3], a[4], a[5]);
    }

    switch (sys_no) {
        case SYS_getcwd:
            SAFE_LOG("[Payload] getcwd\n");
            ret = do_syscall(sys_no, a);
            if (ret > 0 && (const char *)a[0]) {
                const char *host_path = (const char *)a[0];
                const char *guest_path = rewrite_path_from_host(host_path, out_path, sizeof(out_path));
                size_t guest_len = sys_strlen(guest_path);
                if (guest_len + 1 <= (size_t)a[1]) {
                    small_copy((char *)a[0], guest_path);
                    ret = guest_len;
                }
            }
            break;

        case SYS_chdir:
            SAFE_LOG("[Payload] chdir\n");
            if ((const char *)args[0]) {
                args[0] = (long)rewrite_path((const char *)args[0], new_path, sizeof(new_path));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            break;

        case SYS_mknodat:
            SAFE_LOG("[Payload] mknodat\n");
            if ((const char *)args[1]) {
                args[1] = (long)rewrite_path((const char *)args[1], new_path, sizeof(new_path));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            break;

        case SYS_mkdirat:
            SAFE_LOG("[Payload] mkdirat\n");
            if ((const char *)args[1]) {
                args[1] = (long)rewrite_path((const char *)args[1], new_path, sizeof(new_path));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            break;

        case SYS_unlinkat:
            SAFE_LOG("[Payload] unlinkat\n");
            if ((const char *)args[1]) {
                args[1] = (long)rewrite_path((const char *)args[1], new_path, sizeof(new_path));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            break;

        case SYS_linkat:
            SAFE_LOG("[Payload] linkat\n");
            if ((const char *)args[1]) {
                args[1] = (long)rewrite_path((const char *)args[1], new_path, sizeof(new_path));
            }
            if ((const char *)args[3]) {
                args[3] = (long)rewrite_path((const char *)args[3], new_path2, sizeof(new_path2));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            break;

        case SYS_renameat:
            SAFE_LOG("[Payload] renameat\n");
            if ((const char *)args[1]) {
                args[1] = (long)rewrite_path((const char *)args[1], new_path, sizeof(new_path));
            }
            if ((const char *)args[3]) {
                args[3] = (long)rewrite_path((const char *)args[3], new_path2, sizeof(new_path2));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            break;

        case SYS_openat:
            SAFE_LOG("[Payload] openat\n");
            if ((const char *)a[1]) {
                a[1] = (long)rewrite_path((const char *)a[1], new_path, sizeof(new_path));
            }
            ret = do_syscall(sys_no, a);
            break;
            
        case SYS_faccessat:
            SAFE_LOG("[Payload] faccessat\n");
            if ((const char *)a[1]) {
                a[1] = (long)rewrite_path((const char *)a[1], new_path, sizeof(new_path));
            }
            ret = do_syscall(sys_no, a);
            break;

        case SYS_symlinkat:
            SAFE_LOG("[Payload] symlinkat\n");
            if ((const char *)args[0]) {
                args[0] = (long)rewrite_path((const char *)args[0], new_path, sizeof(new_path));
            }
            if ((const char *)args[2]) {
                args[2] = (long)rewrite_path((const char *)args[2], new_path2, sizeof(new_path2));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            break;

        case SYS_readlinkat:
            SAFE_LOG("[Payload] readlinkat\n");
            if ((const char *)args[1]) {
                args[1] = (long)rewrite_path((const char *)args[1], new_path, sizeof(new_path));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            if (ret > 0 && args[2] && args[3] > 0) {
                long copy_len = ret;
                if (copy_len > args[3])
                    copy_len = args[3];
                char tmp[CONFIG_MAX_PATH];
                long max_copy = (long)(sizeof(tmp) - 1);
                if (copy_len > max_copy)
                    copy_len = max_copy;
                char *dst = tmp;
                char *src = (char *)args[2];
                for (long i = 0; i < copy_len; i++)
                    dst[i] = src[i];
                dst[copy_len] = '\0';

                const char *rewritten = rewrite_path_from_host(tmp, out_path, sizeof(out_path));
                size_t new_len = sys_strlen(rewritten);
                size_t cap = (size_t)args[3];
                size_t out_len = new_len < cap ? new_len : cap;
                for (size_t i = 0; i < out_len; i++)
                    ((char *)args[2])[i] = rewritten[i];
                ret = (long)new_len;
            }
            break;

        case SYS_newfstatat:
            SAFE_LOG("[Payload] newfstatat\n");
            if ((const char *)args[1]) {
                args[1] = (long)rewrite_path((const char *)args[1], new_path, sizeof(new_path));
            }
            ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            break;

        case SYS_execve:
            SAFE_LOG("[Payload] execve\n");
            int chain_loader = 1;
            if ((const char *)args[0]) {
                args[0] = (long)rewrite_path((const char *)args[0], new_path, sizeof(new_path));
            }
            log_cstr("[Payload] execve argv0=", (const char *)args[0]);
            /* Copy/rewrite argv/envp into payload stack to avoid touching caller memory */
            char *argv_out[MAX_EXEC_ARGS];
            char *env_out[MAX_EXEC_ENVS];
            char argv_buf[MAX_EXEC_ARGS][CONFIG_MAX_PATH];
            char env_buf[MAX_EXEC_ENVS][CONFIG_MAX_PATH];

            int argv_ok = build_exec_vec((const char *const *)args[1], argv_out,
                                         argv_buf, MAX_EXEC_ARGS, 1 /*rewrite paths*/);
            int env_ok = build_exec_env((const char *const *)args[2], env_out,
                                        env_buf, MAX_EXEC_ENVS);

            if (chain_loader) {
                /* Force chain into loader: <resolved loader> <target> <orig args...> */
                char loader_path[CONFIG_MAX_PATH];
                if (!find_loader_path(loader_path, sizeof(loader_path))) {
                    SAFE_LOG("[Payload] execve chain loader missing, abort\n");
                    ret = -ENOENT;
                    break;
                }

                size_t argc_count = 0;
                while (argc_count < MAX_EXEC_ARGS && argv_out[argc_count])
                    argc_count++;

                char *loader_argv[MAX_EXEC_ARGS];
                size_t lidx = 0;
                loader_argv[lidx++] = loader_path;
                /* Propagate config path via "-c <path>" */
                if (g_payload_config.config_path[0] && lidx + 2 < MAX_EXEC_ARGS) {
                    static const char opt_c[] = "-c";
                    rewrite_path(g_payload_config.config_path, cfg_path, sizeof(cfg_path));
                    loader_argv[lidx++] = (char *)opt_c;
                    loader_argv[lidx++] = cfg_path;
                }
                if (argc_count > 0 && lidx < MAX_EXEC_ARGS) {
                    loader_argv[lidx++] = argv_out[0]; /* target path (rewritten) */
                    for (size_t i = 1; i < argc_count && lidx + 1 < MAX_EXEC_ARGS; i++)
                        loader_argv[lidx++] = argv_out[i];
                }
                if (lidx < MAX_EXEC_ARGS)
                    loader_argv[lidx] = NULL;

                int loader_ok = (lidx < MAX_EXEC_ARGS);

                if (argv_ok && env_ok && loader_ok) {
                    log_cstr("[Payload] execve chain loader=", loader_path);
                    if (argc_count > 0)
                        log_cstr("[Payload] execve chain target=", argv_out[0]);
                    /* Propagate marker to avoid accidental external use */
                    size_t env_count = 0;
                    while (env_count < MAX_EXEC_ENVS && env_out[env_count])
                        env_count++;
                    if (env_count + 1 < MAX_EXEC_ENVS) {
                        static const char marker[] = "HOOK_CHAIN_LOADER=1";
                        size_t idx = env_count;
                        safe_cpy(env_buf[idx], sizeof(env_buf[idx]), marker);
                        env_out[idx] = env_buf[idx];
                        env_out[idx + 1] = NULL;
                    }
                    args[0] = (long)loader_path;
                    args[1] = (long)loader_argv;
                    args[2] = (long)env_out;
                    ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
                } else {
                    SAFE_LOG("[Payload] execve argv/env overflow, falling back\n");
                    /* Fallback to original pointers to avoid truncation */
                    ret = raw_syscall(sys_no, args[0], a[1], a[2], a[3], a[4], a[5]);
                }
            } else {
                if (argv_ok && env_ok) {
                    args[1] = (long)argv_out;
                    args[2] = (long)env_out;
                    ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
                } else {
                    SAFE_LOG("[Payload] execve argv/env overflow, falling back\n");
                    ret = raw_syscall(sys_no, args[0], a[1], a[2], a[3], a[4], a[5]);
                }
            }
            break;

        case SYS_exit:
        case SYS_exit_group:
            SAFE_LOG("[Payload] exit\n");
            ret = do_syscall(sys_no, a);
            break;

        default:
            ret = do_syscall(sys_no, a);
            break;
    }

    return ret;
}
