/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Chain guest execution through the signed loader, preserving root/binds and
 * caller argv/env. This is a first, bounded ELF/single-shebang implementation. */
#include <asm/stat.h>
#include <asm/unistd.h>
#include <linux/fcntl.h>
#include <errno.h>
#include <elf.h>
#include <string.h>
#include "config.h"
#include "syscall_nums.h"
#include "proot_bridge.h"
#include "proot_scratch.h"
#ifdef FD_EXPERIMENT
#include "fd_experiment.h"
#endif

#define EXEC_ARGS 128
#define CHAIN_ARGS (EXEC_ARGS + 32 + CONFIG_MAX_BINDS * 2)
#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFLNK 0120000
extern long raw_syscall(long, long, long, long, long, long, long);

typedef struct {
    char guest[CONFIG_MAX_PATH], host[CONFIG_MAX_PATH];
    char interpreter_guest[CONFIG_MAX_PATH], interpreter_host[CONFIG_MAX_PATH];
    char header[256];
    char volumes[CONFIG_MAX_BINDS][CONFIG_MAX_PATH * 2 + 2];
    char *argv[CHAIN_ARGS];
#ifdef FD_EXPERIMENT
    char fd_state[24];
    /* PT_INTERP as stored in the target, then its policy-checked resolution. */
    char elf_interp[CONFIG_MAX_PATH];
    char elf_interp_guest[CONFIG_MAX_PATH], elf_interp_host[CONFIG_MAX_PATH];
    Elf64_Phdr phdrs[64];
#endif
} ExecScratch;

size_t proot_exec_scratch_size(void) { return sizeof(ExecScratch); }

static int read_executable(const char *path, int nofollow, char header[256])
{
    struct stat st;
    long ret = raw_syscall(SYS_newfstatat, AT_FDCWD, (long)path, (long)&st,
                          AT_SYMLINK_NOFOLLOW, 0, 0);
    if (ret < 0)
        return (int)ret;
    if (nofollow && (st.st_mode & S_IFMT) == S_IFLNK)
        return -ELOOP;
    if ((st.st_mode & S_IFMT) != S_IFREG || !(st.st_mode & 0111))
        return -EACCES;
    ret = raw_syscall(SYS_faccessat, AT_FDCWD, (long)path, 1, 0, 0, 0);
    if (ret < 0)
        return (int)ret;
    long fd = raw_syscall(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0)
        return (int)fd;
    ret = raw_syscall(SYS_read, fd, (long)header, 255, 0, 0, 0);
    raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    if (ret < 0)
        return (int)ret;
    header[ret] = 0;
    return (int)ret;
}

static int elf_magic(const char *p, int n)
{
    if (n < (int)sizeof(Elf64_Ehdr))
        return 0;
    /* Copy into aligned storage: callers may pass an unaligned byte buffer. */
    Elf64_Ehdr h;
    memcpy(&h, p, sizeof(h));
    return h.e_ident[0] == 127 && h.e_ident[1] == 'E' &&
        h.e_ident[2] == 'L' && h.e_ident[3] == 'F' &&
        h.e_ident[EI_CLASS] == ELFCLASS64 &&
        h.e_ident[EI_DATA] == ELFDATA2LSB &&
        h.e_ident[EI_VERSION] == EV_CURRENT && h.e_version == EV_CURRENT &&
        h.e_machine == EM_AARCH64 && (h.e_type == ET_EXEC || h.e_type == ET_DYN) &&
        h.e_ehsize == sizeof(Elf64_Ehdr) &&
        h.e_phentsize == sizeof(Elf64_Phdr) && h.e_phnum > 0;
}

#ifdef FD_EXPERIMENT
/* Read the target's PT_INTERP string. 0: static, 1: found, <0: refused.
 * Bounded like the loader: a non-empty pathname ending in NUL. */
static int elf_interpreter(const char *path, ExecScratch *s)
{
    long fd = raw_syscall(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return (int)fd;
    Elf64_Ehdr h;
    long ret = raw_syscall(__NR_pread64, fd, (long)&h, sizeof(h), 0, 0, 0);
    if (ret == (long)sizeof(h)) {
        size_t bytes = (size_t)h.e_phnum * sizeof(Elf64_Phdr);
        if (!h.e_phnum || h.e_phnum > sizeof(s->phdrs) / sizeof(s->phdrs[0]) ||
            h.e_phentsize != sizeof(Elf64_Phdr)) ret = -ENOEXEC;
        else ret = raw_syscall(__NR_pread64, fd, (long)s->phdrs, (long)bytes,
                               (long)h.e_phoff, 0, 0) == (long)bytes ? 0 : -ENOEXEC;
    } else if (ret >= 0) ret = -ENOEXEC;
    for (size_t i = 0; !ret && i < h.e_phnum; i++) {
        const Elf64_Phdr *p = &s->phdrs[i];
        if (p->p_type != PT_INTERP) continue;
        if (p->p_filesz < 2 || p->p_filesz > sizeof(s->elf_interp)) { ret = -ENOEXEC; break; }
        ret = raw_syscall(__NR_pread64, fd, (long)s->elf_interp, (long)p->p_filesz,
                          (long)p->p_offset, 0, 0);
        if (ret != (long)p->p_filesz || s->elf_interp[p->p_filesz - 1] ||
            !s->elf_interp[0]) { ret = -ENOEXEC; break; }
        ret = 1;
    }
    raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return (int)ret;
}
#endif

long proot_execve_context(long number, long a[6], const struct proot_path_context *context)
{
    int at = number == SYS_execveat;
    int dirfd = at ? (int)a[0] : AT_FDCWD;
    int flags = at ? (int)a[4] : 0;
    const char *path = (const char *)a[at ? 1 : 0];
    char *const *argv = (void *)a[at ? 2 : 1];
    char *const *env = (void *)a[at ? 3 : 2];
    payload_config_t *cfg = &g_payload_config;
    if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
        return -EINVAL;
    if (!path)
        return -EFAULT;
    if (!*path)
        return (flags & AT_EMPTY_PATH) ? -EOPNOTSUPP : -ENOENT;
    /* Preserve debugger policy explicitly rather than silently losing it. */
    if (cfg->hook_range_set || cfg->hook_range_interp_set)
        return -EOPNOTSUPP;
    if (!cfg->loader_path[0])
        return -ENOENT;
    size_t argc = 0;
    while (argv && argv[argc]) {
        if (++argc >= EXEC_ARGS)
            return -E2BIG;
    }
    long mem = proot_scratch_alloc(sizeof(ExecScratch));
    if ((unsigned long)mem >= (unsigned long)-4095)
        return mem;
    ExecScratch *s = (void *)mem;
#ifdef FD_EXPERIMENT
    long transport = -1;
#endif
    long ret = proot_resolve_exec_path(dirfd, path, !(flags & AT_SYMLINK_NOFOLLOW),
                                       s->guest, s->host, sizeof(s->host), context);
    if (ret < 0)
        goto done;
    if (!strcmp(s->host, cfg->loader_path)) {
        ret = -EPERM;
        goto done;
    }
    int n = read_executable(s->host, flags & AT_SYMLINK_NOFOLLOW, s->header);
    if (n < 0) { ret = n; goto done; }
    char *target = s->host;
    char *interpreter = NULL, *optional_arg = NULL;
    int script = !elf_magic(s->header, n);
    if (script) {
        if (n < 3 || s->header[0] != '#' || s->header[1] != '!') {
            ret = -ENOEXEC;
            goto done;
        }
        char *end = strchr(s->header, '\n');
        if (!end && n == 255) { ret = -ENOEXEC; goto done; }
        if (end) *end = 0;
        end = s->header + strlen(s->header);
        while (end > s->header && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
        interpreter = s->header + 2;
        while (*interpreter == ' ' || *interpreter == '\t') interpreter++;
        char *arg = interpreter;
        while (*arg && *arg != ' ' && *arg != '\t') arg++;
        if (*arg) {
            *arg++ = 0;
            while (*arg == ' ' || *arg == '\t') arg++;
            if (*arg) optional_arg = arg;
        }
        if (!*interpreter) { ret = -ENOEXEC; goto done; }
        ret = proot_resolve_exec_path(AT_FDCWD, interpreter, true,
                                      s->interpreter_guest, s->interpreter_host,
                                      sizeof(s->interpreter_host), context);
        if (ret < 0) goto done;
        /* Nested script interpreters require a bounded interpreter stack. */
        char magic[256];
        n = read_executable(s->interpreter_host, 0, magic);
        if (n < 0) { ret = n; goto done; }
        if (!elf_magic(magic, n)) { ret = -EOPNOTSUPP; goto done; }
        target = s->interpreter_host;
    }
#ifdef FD_EXPERIMENT
    int dynamic = 0;
    if (cfg->guard_file_reads) {
        /* The dynamic linker is loaded content too: resolve it with guest
         * symlinks and the read policy instead of lexical host mapping. */
        dynamic = elf_interpreter(target, s);
        if (dynamic < 0) { ret = dynamic; goto done; }
        if (dynamic) {
            ret = proot_resolve_exec_path(AT_FDCWD, s->elf_interp, true,
                                          s->elf_interp_guest, s->elf_interp_host,
                                          sizeof(s->elf_interp_host), context);
            if (ret < 0) goto done;
            char magic[256];
            n = read_executable(s->elf_interp_host, 0, magic);
            if (n < 0) { ret = n; goto done; }
            if (!elf_magic(magic, n)) { ret = -ELIBBAD; goto done; }
        }
    }
#endif
    size_t pos = 0;
    s->argv[pos++] = cfg->loader_path;
    s->argv[pos++] = "--child-loader";
    s->argv[pos++] = "--mode";
    s->argv[pos++] = cfg->mode == CONFIG_MODE_CONTAINER ? "container" : "compat";
    if (cfg->root[0]) {
        s->argv[pos++] = "--root";
        s->argv[pos++] = cfg->root;
    }
    for (int i = 0; i < cfg->bind_count; i++) {
        /* CLI serializes volumes as host:guest. Colons need a richer protocol. */
        if (strchr(cfg->binds[i].src, ':') || strchr(cfg->binds[i].dst, ':')) {
            ret = -EOPNOTSUPP;
            goto done;
        }
        strcpy(s->volumes[i], cfg->binds[i].dst);
        strcat(s->volumes[i], ":");
        strcat(s->volumes[i], cfg->binds[i].src);
        s->argv[pos++] = "-v";
        s->argv[pos++] = s->volumes[i];
    }
    s->argv[pos++] = "--exec-target";
    s->argv[pos++] = target;
    s->argv[pos++] = "--exec-path";
    s->argv[pos++] = s->guest;
    /* The kernel's exe for a script is its interpreter. */
    s->argv[pos++] = CONFIG_CHILD_EXEC_EXE;
    s->argv[pos++] = script ? s->interpreter_guest : s->guest;
    /* Kernel comm: basename of the path as passed (symlink name included). */
    const char *name = path;
    for (const char *p = path; *p; p++)
        if (*p == '/' && p[1]) name = p + 1;
    if (*name && *name != '/') {
        s->argv[pos++] = CONFIG_CHILD_EXEC_NAME;
        s->argv[pos++] = (char *)name;
    }
#ifdef FD_EXPERIMENT
    if (dynamic) {
        s->argv[pos++] = CONFIG_CHILD_EXEC_INTERP;
        s->argv[pos++] = s->elf_interp_host;
    }
#endif
#ifdef FD_EXPERIMENT
    if (cfg->mount_access_observe[0]) {
        s->argv[pos++] = cfg->guard_file_reads ? "--guard-file-access" :
            cfg->guard_path_mutations == 2 ? "--guard-file-mutations" :
            cfg->guard_path_mutations ? "--guard-path-mutations" : "--observe-mount-access";
        s->argv[pos++] = cfg->mount_access_observe;
    }
    if (cfg->revalidate_file_fds)s->argv[pos++] = "--revalidate-file-fds";
    if (cfg->allow_pipe_output)s->argv[pos++] = "--allow-pipe-output";
    if (cfg->allow_local_output)s->argv[pos++] = "--allow-local-output";
    if (cfg->allow_stdio_output)s->argv[pos++] = "--allow-stdio-output";
    if (cfg->allow_stream_input)s->argv[pos++] = "--allow-stream-input";
    transport = fd_experiment_export();
    if (transport < 0) { ret = transport; goto done; }
    unsigned value = (unsigned)transport;
    char *digit = s->fd_state + sizeof(s->fd_state) - 1;
    *digit = 0;
    do { *--digit = '0' + value % 10; value /= 10; } while (value);
    s->argv[pos++] = "--fd-state";
    s->argv[pos++] = digit;
#endif
    s->argv[pos++] = "--";
    if (script) {
        s->argv[pos++] = interpreter;
        if (optional_arg) s->argv[pos++] = optional_arg;
        s->argv[pos++] = s->guest;
        for (size_t i = 1; i < argc; i++) s->argv[pos++] = argv[i];
    } else if (argc) {
        for (size_t i = 0; i < argc; i++) s->argv[pos++] = argv[i];
    } else {
        s->argv[pos++] = "";
    }
    s->argv[pos] = NULL;
    /* The signed loader starts the same embedded backend. Do not fall back
     * to raw target exec, which would lose the guest filesystem view. */
#ifdef FD_EXPERIMENT
    ret = raw_syscall(__NR_fcntl, transport, F_SETFD, 0, 0, 0, 0);
    if (ret < 0) goto done;
#endif
    ret = raw_syscall(SYS_execve, (long)cfg->loader_path, (long)s->argv,
                      (long)env, 0, 0, 0);
 done:
#ifdef FD_EXPERIMENT
    if (transport >= 0) raw_syscall(__NR_close, transport, 0, 0, 0, 0, 0);
#endif
    proot_scratch_free((void *)mem,sizeof(ExecScratch));
    return ret;
}

long proot_execve(long number, long args[6])
{
    return proot_execve_context(number, args, NULL);
}
