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
#include "fake_ids.h"
#include "reentry_guard.h"
#include "syscall_nums.h"
#include "proot_bridge.h"
#include "proot_scratch.h"
#ifdef FD_EXPERIMENT
#include "fd_experiment.h"
#endif

/* Guest argv entries held inline; longer vectors get their own mapping. */
#define EXEC_ARGS 128
/* The kernel bounds argv by bytes (E2BIG at execve), not by count. */
#define MAX_ARGS (1 << 20)
/* Script levels the kernel follows (exec_binprm allows five rewrites
 * before ELOOP): the script plus four script interpreters. */
#define SCRIPT_DEPTH 5
#define CHAIN_EXTRA (64 + SCRIPT_DEPTH * 2 + CONFIG_MAX_BINDS * 2)
#define CHAIN_ARGS (EXEC_ARGS + CHAIN_EXTRA)
#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFLNK 0120000
extern long raw_syscall(long, long, long, long, long, long, long);

typedef struct {
    char guest[CONFIG_MAX_PATH], host[CONFIG_MAX_PATH];
    char interpreter_guest[CONFIG_MAX_PATH], interpreter_host[CONFIG_MAX_PATH];
    char header[SCRIPT_DEPTH + 1][256];
    char volumes[CONFIG_MAX_BINDS][CONFIG_MAX_PATH * 2 + 2];
    char **argv;
    char *inline_argv[CHAIN_ARGS];
    char fake_ids[8 * 11];
    char fake_groups[32 * 11 + 2];
    char exec_fd[16];
#ifdef FD_EXPERIMENT
    char fd_state[24];
    /* PT_INTERP as stored in the target, then its policy-checked resolution. */
    char elf_interp[CONFIG_MAX_PATH];
    char elf_interp_guest[CONFIG_MAX_PATH], elf_interp_host[CONFIG_MAX_PATH];
    Elf64_Phdr phdrs[64];
#endif
} ExecScratch;

size_t proot_exec_scratch_size(void) { return sizeof(ExecScratch); }

static void fd_name(char *out, const char *prefix, int fd)
{
    char digits[12];
    int count = 0;
    unsigned value = (unsigned)fd;
    strcpy(out, prefix);
    out += strlen(out);
    do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) *out++ = digits[--count];
    *out = 0;
}

static int read_executable(const char *path, int nofollow, char header[256])
{
    struct stat st;
    /* Resolved host paths are final; /proc/self/fd/N (fexecve) is followed. */
    long ret = raw_syscall(SYS_newfstatat, AT_FDCWD, (long)path, (long)&st,
                          nofollow ? AT_SYMLINK_NOFOLLOW : 0, 0, 0);
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
    /* fexecve runs the object the FD names, never whatever its name
     * resolves to now: the child loader opens it through /proc/self/fd. Like
     * the kernel, only a regular executable qualifies (a directory or an
     * O_PATH symlink FD is EACCES), AT_EXECFN and a script's file argument
     * are /dev/fd/N, and a script behind an O_CLOEXEC FD is ENOENT. */
    char fd_host[32] = "", fd_guest[32] = "";
    char named[CONFIG_MAX_PATH] = "";
    int exec_fd = -1;
    if (!*path) {
        if (!(flags & AT_EMPTY_PATH))
            return -ENOENT;
        struct stat st;
        long rc = raw_syscall(__NR_fstat, dirfd, (long)&st, 0, 0, 0, 0);
        if (rc < 0)
            return rc;
        if ((st.st_mode & S_IFMT) != S_IFREG)
            return -EACCES;
        fd_name(fd_host, "/proc/self/fd/", dirfd);
        fd_name(fd_guest, "/dev/fd/", dirfd);
        rc = raw_syscall(SYS_faccessat, AT_FDCWD, (long)fd_host, 1, 0, 0, 0);
        if (rc < 0)
            return rc;
        /* /proc/self/exe: the guest name, else the kernel's own link text. */
        if (proot_fd_guest_path(dirfd, named, sizeof(named)) < 0) {
            rc = raw_syscall(SYS_readlinkat, AT_FDCWD, (long)fd_host, (long)named,
                             sizeof(named) - 1, 0, 0);
            named[rc > 0 ? rc : 0] = 0;
            if (rc <= 0) strcpy(named, fd_guest);
        }
        exec_fd = dirfd;
        path = fd_guest;
    }
    /* Preserve debugger policy explicitly rather than silently losing it. */
    if (cfg->hook_range_set || cfg->hook_range_interp_set)
        return -EOPNOTSUPP;
    if (!cfg->loader_path[0])
        return -ENOENT;
    size_t argc = 0;
    while (argv && argv[argc]) {
        if (++argc >= MAX_ARGS)
            return -E2BIG;
    }
    long mem = proot_scratch_alloc(sizeof(ExecScratch));
    if ((unsigned long)mem >= (unsigned long)-4095)
        return mem;
    ExecScratch *s = (void *)mem;
    /* A large vector is mapped separately (a vfork child's exec leaves it in
     * the shared parent, like any memory a vfork child allocates). */
    size_t argv_bytes = 0;
    s->argv = s->inline_argv;
    if (argc >= EXEC_ARGS) {
        argv_bytes = (argc + CHAIN_EXTRA) * sizeof(char *);
        long array = raw_syscall(__NR_mmap, 0, (long)argv_bytes, 3, 0x22, -1, 0);
        if ((unsigned long)array >= (unsigned long)-4095) {
            proot_scratch_free((void *)mem, sizeof(ExecScratch));
            return array;
        }
        s->argv = (char **)array;
    }
#ifdef FD_EXPERIMENT
    long transport = -1;
#endif
    long ret;
    long fd_copy = -1;
    if (exec_fd >= 0) {
        /* The guest's FD may be close-on-exec: the chain gets its own copy,
         * which the child loader closes once it has opened the program. */
        fd_copy = raw_syscall(__NR_fcntl, exec_fd, F_DUPFD, 3, 0, 0, 0);
        if (fd_copy < 0) { ret = fd_copy; goto done; }
        fd_name(s->host, "/proc/self/fd/", (int)fd_copy);
        strcpy(s->guest, named);
    } else {
        ret = proot_resolve_exec_path(dirfd, path, !(flags & AT_SYMLINK_NOFOLLOW),
                                      s->guest, s->host, sizeof(s->host), context);
        if (ret < 0)
            goto done;
    }
    if (!strcmp(s->host, cfg->loader_path)) {
        ret = -EPERM;
        goto done;
    }
    int n = read_executable(s->host, flags & AT_SYMLINK_NOFOLLOW, s->header[0]);
    if (n < 0) { ret = n; goto done; }
    char *target = s->host;
    /* Like the kernel, an interpreter may itself be a script: level i's
     * interpreter and optional argument are names[i] and options[i]. */
    char *names[SCRIPT_DEPTH], *options[SCRIPT_DEPTH];
    int depth = 0;
    while (!elf_magic(s->header[depth], n)) {
        char *header = s->header[depth];
        if (n < 3 || header[0] != '#' || header[1] != '!') {
            ret = -ENOEXEC;
            goto done;
        }
        if (depth == SCRIPT_DEPTH) { ret = -ELOOP; goto done; }
        char *end = strchr(header, '\n');
        if (!end && n == 255) { ret = -ENOEXEC; goto done; }
        if (end) *end = 0;
        end = header + strlen(header);
        while (end > header && (end[-1] == ' ' || end[-1] == '\t')) *--end = 0;
        char *interpreter = header + 2, *optional_arg = NULL;
        while (*interpreter == ' ' || *interpreter == '\t') interpreter++;
        char *arg = interpreter;
        while (*arg && *arg != ' ' && *arg != '\t') arg++;
        if (*arg) {
            *arg++ = 0;
            while (*arg == ' ' || *arg == '\t') arg++;
            if (*arg) optional_arg = arg;
        }
        if (!*interpreter) { ret = -ENOEXEC; goto done; }
        if (!depth && exec_fd >= 0) {
            long fd_flags = raw_syscall(__NR_fcntl, exec_fd, F_GETFD, 0, 0, 0, 0);
            if (fd_flags < 0 || (fd_flags & FD_CLOEXEC)) { ret = -ENOENT; goto done; }
        }
        names[depth] = interpreter;
        options[depth++] = optional_arg;
        ret = proot_resolve_exec_path(AT_FDCWD, interpreter, true,
                                      s->interpreter_guest, s->interpreter_host,
                                      sizeof(s->interpreter_host), context);
        if (ret < 0) goto done;
        n = read_executable(s->interpreter_host, 0, s->header[depth]);
        if (n < 0) { ret = n; goto done; }
        target = s->interpreter_host;
    }
    int script = depth > 0;
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
    s->argv[pos++] = exec_fd >= 0 ? fd_guest : s->guest;
    if (exec_fd >= 0) {
        fd_name(s->exec_fd, "", (int)fd_copy);
        s->argv[pos++] = CONFIG_CHILD_EXEC_FD;
        s->argv[pos++] = s->exec_fd;
    }
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
    uint32_t ids[8];
    int changed = fake_ids_current(ids);
    /* A set-user/group-ID program (the final ELF, interpreter for scripts)
     * runs with its reported owner as effective, saved and fs id, like
     * PRoot's fake_id0; only the new image gets them. */
    struct stat program;
    if (!raw_syscall(SYS_newfstatat, AT_FDCWD, (long)target, (long)&program, 0, 0, 0)) {
        for (int group = 0; group < 2; group++) {
            if (!(program.st_mode & (group ? 02000 : 04000))) continue;
            uint32_t owner = fake_reported_owner(group ? program.st_gid : program.st_uid, group);
            ids[group * 4 + 1] = ids[group * 4 + 2] = ids[group * 4 + 3] = owner;
            changed |= owner != 0;
        }
    }
    if (changed) {
        char *out = s->fake_ids;
        for (int i = 0; i < 8; i++) {
            char digits[12];
            int count = 0;
            uint32_t value = ids[i];
            do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
            while (count) *out++ = digits[--count];
            *out++ = i < 7 ? ':' : 0;
        }
        s->argv[pos++] = CONFIG_CHILD_FAKE_IDS;
        s->argv[pos++] = s->fake_ids;
    }
    if (cfg->link_copy) s->argv[pos++] = "--link-copy";
    if (cfg->seccomp_backstop) s->argv[pos++] = "--seccomp-backstop";
    uint32_t groups[32];
    int group_count = fake_ids_groups(groups);
    if (group_count != 1 || groups[0]) {
        char *out = s->fake_groups;
        if (!group_count) *out++ = '-';
        for (int i = 0; i < group_count; i++) {
            char digits[12];
            int count = 0;
            uint32_t value = groups[i];
            do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
            while (count) *out++ = digits[--count];
            if (i + 1 < group_count) *out++ = ',';
        }
        *out = 0;
        s->argv[pos++] = CONFIG_CHILD_FAKE_GROUPS;
        s->argv[pos++] = s->fake_groups;
    }
    if (cfg->kernel_release[0]) {
        s->argv[pos++] = "--kernel-release";
        s->argv[pos++] = cfg->kernel_release;
    }
    if (cfg->kernel_sysname[0]) {
        s->argv[pos++] = "--kernel-sysname";
        s->argv[pos++] = cfg->kernel_sysname;
    }
    if (cfg->glue_dir[0]) {
        s->argv[pos++] = CONFIG_CHILD_GLUE_DIR;
        s->argv[pos++] = (char *)cfg->glue_dir;
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
        /* Innermost interpreter first; each level's file is the name the
         * previous level's line gave, the outermost one the script itself. */
        for (int level = depth - 1; level >= 0; level--) {
            s->argv[pos++] = names[level];
            if (options[level]) s->argv[pos++] = options[level];
        }
        s->argv[pos++] = exec_fd >= 0 ? fd_guest : s->guest;
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
    struct reentry_slot *lease = reentry_exec_release();
    ret = raw_syscall(SYS_execve, (long)cfg->loader_path, (long)s->argv,
                      (long)env, 0, 0, 0);
    reentry_exec_restore(lease);
 done:
#ifdef FD_EXPERIMENT
    if (transport >= 0) raw_syscall(__NR_close, transport, 0, 0, 0, 0, 0);
#endif
    if (fd_copy >= 0) raw_syscall(__NR_close, fd_copy, 0, 0, 0, 0, 0);
    if (argv_bytes) raw_syscall(__NR_munmap, (long)s->argv, (long)argv_bytes, 0, 0, 0, 0);
    proot_scratch_free((void *)mem,sizeof(ExecScratch));
    return ret;
}

long proot_execve(long number, long args[6])
{
    return proot_execve_context(number, args, NULL);
}
