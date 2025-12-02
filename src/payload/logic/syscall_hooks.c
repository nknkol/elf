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

static void small_copy(char *dst, const char *src)
{
    if (!dst || !src) return;
    while (*src) {
        *dst++ = *src++;
    }
    *dst = 0;
}

static int path_exists(const char *path)
{
    if (!path || !path[0])
        return 0;
    long r = raw_syscall(SYS_faccessat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    return r == 0;
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
                args[1] = (long)rewrite_path((const char *)args[1], new_path, sizeof(new_path));
            }

            if (sys_no == SYS_linkat || sys_no == SYS_renameat || sys_no == SYS_symlinkat) {
                if ((const char *)args[3]) {
                    args[3] = (long)rewrite_path((const char *)args[3], new_path2, sizeof(new_path2));
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

            /* Always force loader chain: rewrite argv[0]/argv and env */
            {
                char argv_buf[MAX_EXEC_ARGS][CONFIG_MAX_PATH];
                char env_buf[MAX_EXEC_ENVS][CONFIG_MAX_PATH];
                char *argv_out[MAX_EXEC_ARGS];
                char *env_out[MAX_EXEC_ENVS];

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

                /* Resolve loader path */
                char loader_path[CONFIG_MAX_PATH];
                if (!find_loader_path(loader_path, sizeof(loader_path))) {
                    SAFE_LOG("[Payload] loader not found\n");
                    ret = -ENOENT;
                    break;
                }

                /* Shift argv right by 1 to insert loader */
                int argc = 0;
                while (argv_out[argc])
                    argc++;
                if (argc + 2 >= MAX_EXEC_ARGS) {
                    ret = -ENOENT;
                    break;
                }
                for (int i = argc; i >= 0; i--) {
                    argv_out[i + 1] = argv_out[i];
                }
                argv_out[0] = loader_path;
                argv_out[argc + 1] = NULL;

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
            ret = do_syscall(sys_no, args);
            if (ret == 0 && (args[2] & PROT_EXEC)) {
                install_hook((void *)args[0], (size_t)args[1], (void *)&_start, 0);
            }
            break;

        case SYS_mmap:
            SAFE_LOG("[Payload] mmap\n");
            ret = do_syscall(sys_no, args);
            if (ret >= 0 && (args[2] & PROT_EXEC)) {
                install_hook((void *)ret, (size_t)args[1], (void *)&_start, 0);
            }
            break;

        default:
            /* Passthrough */
            ret = do_syscall(sys_no, args);
            break;
    }

    return ret;
}
