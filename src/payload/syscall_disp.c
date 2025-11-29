#include "mini_libc.h"
#include "config.h"
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

static inline long do_syscall(long sys_no, long *a) {
    return raw_syscall(sys_no, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static size_t safe_cpy(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0)
        return 0;
    size_t i = 0;
    while (i + 1 < dst_sz && src && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i;
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
        safe_cpy(buf[idx], sizeof(buf[idx]), s);
        if (rewrite_paths) {
            rewrite_path(buf[idx], buf[idx], sizeof(buf[idx]));
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
            if ((const char *)args[0]) {
                args[0] = (long)rewrite_path((const char *)args[0], new_path, sizeof(new_path));
            }
            /* Copy/rewrite argv/envp into payload stack to avoid touching caller memory */
            char *argv_out[MAX_EXEC_ARGS];
            char *env_out[MAX_EXEC_ENVS];
            char argv_buf[MAX_EXEC_ARGS][CONFIG_MAX_PATH];
            char env_buf[MAX_EXEC_ENVS][CONFIG_MAX_PATH];

            int argv_ok = build_exec_vec((const char *const *)args[1], argv_out,
                                         argv_buf, MAX_EXEC_ARGS, 1 /*rewrite paths*/);
            int env_ok = build_exec_vec((const char *const *)args[2], env_out,
                                        env_buf, MAX_EXEC_ENVS, 0 /*copy only*/);

            if (argv_ok && env_ok) {
                args[1] = (long)argv_out;
                args[2] = (long)env_out;
                ret = raw_syscall(sys_no, args[0], args[1], args[2], args[3], args[4], args[5]);
            } else {
                SAFE_LOG("[Payload] execve argv/env overflow, falling back\n");
                /* Fallback to original pointers to avoid truncation */
                ret = raw_syscall(sys_no, args[0], a[1], a[2], a[3], a[4], a[5]);
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
