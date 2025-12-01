#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>

#define __NR_getcwd 17
#define __NR_chdir  49
#define __NR_readlinkat 78
#define __NR_newfstatat 79
#define __NR_mknodat 33
#define __NR_mkdirat 34
#define __NR_unlinkat 35
#define __NR_linkat 37
#define __NR_renameat 38
#define __NR_openat 56
#define __NR_write 64
#define __NR_close 57
#define __NR_symlinkat 36
#define __NR_execve 221

static long my_syscall3(long n, long a1, long a2, long a3) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    register long x1 asm("x1") = a2;
    register long x2 asm("x2") = a3;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2)
                 : "memory", "cc");
    return x0;
}

static long my_syscall1(long n, long a1) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8)
                 : "memory", "cc");
    return x0;
}

static long my_syscall4(long n, long a1, long a2, long a3, long a4) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    register long x1 asm("x1") = a2;
    register long x2 asm("x2") = a3;
    register long x3 asm("x3") = a4;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                 : "memory", "cc");
    return x0;
}

static long my_syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    register long x1 asm("x1") = a2;
    register long x2 asm("x2") = a3;
    register long x3 asm("x3") = a4;
    register long x4 asm("x4") = a5;
    asm volatile("svc #0"
                 : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
                 : "memory", "cc");
    return x0;
}

static void run_execve_case(const char *label, const char *path,
                            const char *const argv[],
                            const char *const envp[])
{
    pid_t pid = fork();
    if (pid == 0) {
        long ret = my_syscall3(__NR_execve, (long)path, (long)argv, (long)envp);
        printf("[demo] %s execve('%s') ret=%ld\n", label, path, ret);
        int code = 0;
        if (ret < 0) {
            code = (int)(-ret);
        } else if (ret > 255) {
            code = 255;
        } else {
            code = (int)ret;
        }
        _exit(code);
    } else if (pid > 0) {
        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            printf("[demo] %s waitpid failed\n", label);
            return;
        }
        if (WIFEXITED(status)) {
            printf("[demo] %s child exit=%d\n", label, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("[demo] %s child killed by signal %d\n", label, WTERMSIG(status));
        }
    } else {
        printf("[demo] %s skipped: fork failed\n", label);
    }
}

int main(void)
{
    char buf[256] = {0};
    long ret;
    struct stat st;

    ret = my_syscall3(__NR_getcwd, (long)buf, sizeof(buf), 0);
    printf("[demo] getcwd ret=%ld buf='%s'\n", ret, buf);

    ret = my_syscall1(__NR_chdir, (long)"/home");
    printf("[demo] chdir('/home') ret=%ld\n", ret);

    buf[0] = 0;
    ret = my_syscall3(__NR_getcwd, (long)buf, sizeof(buf), 0);
    printf("[demo] getcwd after chdir ret=%ld buf='%s'\n", ret, buf);

    buf[0] = 0;
    ret = my_syscall4(__NR_readlinkat, AT_FDCWD, (long)"outside_link", (long)buf, sizeof(buf));
    if (ret >= 0) {
        buf[ret < (long)sizeof(buf) ? ret : (long)sizeof(buf) - 1] = '\0';
    }
    printf("[demo] readlinkat('outside_link') ret=%ld buf='%s'\n", ret, buf);

    ret = my_syscall4(__NR_newfstatat, AT_FDCWD, (long)"/etc/passwd", (long)&st, 0);
    printf("[demo] newfstatat('/etc/passwd') ret=%ld mode=%o\n", ret, ret == 0 ? (unsigned)(st.st_mode & 07777) : 0U);

    const char *mkdir_path = "/home/tmp_hook_dir";
    ret = my_syscall3(__NR_mkdirat, AT_FDCWD, (long)mkdir_path, 0777);
    printf("[demo] mkdirat('%s') ret=%ld\n", mkdir_path, ret);
    ret = my_syscall3(__NR_unlinkat, AT_FDCWD, (long)mkdir_path, AT_REMOVEDIR);
    printf("[demo] unlinkat('%s', AT_REMOVEDIR) ret=%ld\n", mkdir_path, ret);

    const char *unlink_path = "/home/tmp_hook_unlink";
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)unlink_path, 0); /* cleanup */
    long fd_unlink = my_syscall4(__NR_openat, AT_FDCWD, (long)unlink_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_unlink >= 0) {
        const char msg[] = "unlink test";
        (void)my_syscall3(__NR_write, fd_unlink, (long)msg, (long)strlen(msg));
        (void)my_syscall1(__NR_close, fd_unlink);
    }
    ret = my_syscall3(__NR_unlinkat, AT_FDCWD, (long)unlink_path, 0);
    printf("[demo] unlinkat('%s') ret=%ld\n", unlink_path, ret);

    const char *fifo_path = "/home/tmp_hook_fifo";
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)fifo_path, 0);
    ret = my_syscall4(__NR_mknodat, AT_FDCWD, (long)fifo_path, S_IFIFO | 0644, 0);
    printf("[demo] mknodat('%s', FIFO) ret=%ld\n", fifo_path, ret);
    ret = my_syscall3(__NR_unlinkat, AT_FDCWD, (long)fifo_path, 0);
    printf("[demo] unlinkat('%s') ret=%ld\n", fifo_path, ret);

    const char *src = "/home/tmp_rename_src";
    const char *dst = "/home/tmp_rename_dst";
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)dst, 0);
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)src, 0);
    long fd = my_syscall4(__NR_openat, AT_FDCWD, (long)src, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char msg[] = "rename test";
        (void)my_syscall3(__NR_write, fd, (long)msg, (long)strlen(msg));
        (void)my_syscall1(__NR_close, fd);
    }
    ret = my_syscall4(__NR_renameat, AT_FDCWD, (long)src, AT_FDCWD, (long)dst);
    printf("[demo] renameat('%s'->'%s') ret=%ld\n", src, dst, ret);
    ret = my_syscall4(__NR_unlinkat, AT_FDCWD, (long)dst, 0, 0);
    printf("[demo] unlinkat('%s') ret=%ld\n", dst, ret);

    const char *ln_src = "/home/tmp_linkat_src";
    const char *ln_dst = "/home/tmp_linkat_dst";
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)ln_src, 0);
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)ln_dst, 0);
    fd = my_syscall4(__NR_openat, AT_FDCWD, (long)ln_src, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char msg[] = "linkat test";
        (void)my_syscall3(__NR_write, fd, (long)msg, (long)strlen(msg));
        (void)my_syscall1(__NR_close, fd);
    }
    ret = my_syscall5(__NR_linkat, AT_FDCWD, (long)ln_src, AT_FDCWD, (long)ln_dst, 0);
    printf("[demo] linkat('%s'->'%s') ret=%ld\n", ln_src, ln_dst, ret);
    ret = my_syscall3(__NR_unlinkat, AT_FDCWD, (long)ln_dst, 0);
    printf("[demo] unlinkat('%s') ret=%ld\n", ln_dst, ret);
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)ln_src, 0);

    const char *link_target = "/home/tmp_link_target";
    const char *link_path = "/home/tmp_link";
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)link_path, 0);
    fd = my_syscall4(__NR_openat, AT_FDCWD, (long)link_target, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char msg[] = "symlink test";
        (void)my_syscall3(__NR_write, fd, (long)msg, (long)strlen(msg));
        (void)my_syscall1(__NR_close, fd);
    }
    ret = my_syscall3(__NR_symlinkat, (long)link_target, AT_FDCWD, (long)link_path);
    printf("[demo] symlinkat('%s'->'%s') ret=%ld\n", link_target, link_path, ret);
    buf[0] = 0;
    ret = my_syscall4(__NR_readlinkat, AT_FDCWD, (long)link_path, (long)buf, sizeof(buf));
    if (ret >= 0) {
        buf[ret < (long)sizeof(buf) ? ret : (long)sizeof(buf) - 1] = '\0';
    }
    printf("[demo] readlinkat('%s') ret=%ld buf='%s'\n", link_path, ret, buf);
    ret = my_syscall3(__NR_unlinkat, AT_FDCWD, (long)link_path, 0);
    (void)my_syscall3(__NR_unlinkat, AT_FDCWD, (long)link_target, 0);

    /* Execve real target via loader chain: user should place tiny_target alongside demo */
    const char *tiny_path = "/home/tiny_target";
    const char *tiny_argv[] = { tiny_path, "hello", NULL };
    const char *exec_env_chain[] = { "HOOK_CHAIN_LOADER=1", "DEMO_EXECVE=1", "PATH=/home/bin:/usr/bin", "LD_LIBRARY_PATH=/home/lib:/usr/lib", NULL };
    run_execve_case("execve_chain", tiny_path, tiny_argv, exec_env_chain);

    /* Execve failure path to observe hook without exiting process */
    const char *exec_path = "/home/execve_missing";
    const char *exec_argv[] = { exec_path, "/abs_arg", "rel_arg", NULL };
    const char *exec_envp[] = { "DEMO_EXECVE=1", "PATH=/home/bin:/usr/bin", "LD_LIBRARY_PATH=/home/lib:/usr/lib", NULL };
    run_execve_case("execve_missing", exec_path, exec_argv, exec_envp);
    return 0;
}
