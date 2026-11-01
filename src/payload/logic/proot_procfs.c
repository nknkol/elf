/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PRoot path backend, /proc: links of loader-run processes (exe, cwd,
 * fd), their cmdline, readlink of /proc names, and the mount tables
 * generated from the R4 table. */
#include "proot_bridge_internal.h"

static long current_id(long number)
{
    return raw_syscall(number, 0, 0, 0, 0, 0, 0);
}

/* Writes "/proc/<pid>" or "/proc/<pid>/task/<tid>" into out. */
static int format_proc(char *out, long pid, long tid)
{
    char *p = out;
    const char *prefix = "/proc/";
    while (*prefix) *p++ = *prefix++;
    for (int pass = 0; pass < (tid ? 2 : 1); pass++) {
        long value = pass ? tid : pid;
        char digits[24];
        int count = 0;
        do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
        if (pass) { const char *task = "/task/"; while (*task) *p++ = *task++; }
        while (count) *p++ = digits[--count];
    }
    *p = 0;
    return FS_LINK_CANONICALIZE;
}

/* A loader-run process's kernel cmdline is the loader's own: loader options,
 * "--", then the guest argv (exactly what the guest received). Returns the
 * offset of the guest argv in proc_data and its length, or 0 if pid is not
 * loader-run or has no separator. exe receives --exec-exe when present. */
static long loader_argv(Bridge *b, long pid, size_t *start, const char **exe)
{
    char path[48];
    format_proc(path, pid, 0);
    strcat(path, "/cmdline");
    long fd = raw_syscall(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return 0;
    long total = 0, n;
    while (total < (long)sizeof(b->proc_data) &&
           (n = raw_syscall(__NR_read, fd, (long)b->proc_data + total,
                            sizeof(b->proc_data) - total, 0, 0, 0)) > 0)
        total += n;
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    if (total <= 0 || total == (long)sizeof(b->proc_data) || b->proc_data[total - 1]) return 0;
    if (!g_payload_config.loader_path[0] || strcmp(b->proc_data, g_payload_config.loader_path))
        return 0;
    *exe = NULL;
    for (long at = (long)strlen(b->proc_data) + 1; at < total; at += (long)strlen(b->proc_data + at) + 1) {
        const char *arg = b->proc_data + at;
        if (!strcmp(arg, "--")) {
            *start = (size_t)(at + 3);
            return total - (long)*start;
        }
        if (!strcmp(arg, CONFIG_CHILD_EXEC_EXE) && at + 15 < total)
            *exe = b->proc_data + at + strlen(arg) + 1;
    }
    return 0;
}

/* PRoot's readlink_proc without a PID namespace: guest PIDs are kernel PIDs.
 * self/thread-self canonicalize to the caller; this process's exe is the guest
 * program (the kernel link names the loader); cwd, root and other processes'
 * exe are kernel targets reported in guest terms; fd entries stay magic links
 * when final (PRoot's DONT_CANONICALIZE), except under the read guard, where
 * a file target is resolved by its guest path so the policy applies. */
int pb_proc_link(void *opaque, char *out, const char *path,
                     const char *component, Comparison comparison)
{
    Bridge *b = opaque;
    if (comparison == PATHS_ARE_EQUAL) {
        if (!strcmp(component, "self"))
            return format_proc(out, current_id(__NR_getpid), 0);
        if (!strcmp(component, "thread-self"))
            return format_proc(out, current_id(__NR_getpid), current_id(__NR_gettid));
        return FS_LINK_DEFAULT;
    }
    if (comparison != PATH1_IS_PREFIX) return FS_LINK_DEFAULT;
    const char *cursor = path + strlen("/proc/");
    long pid = 0;
    /* Uncanonicalized self names: the broker resolves them to the caller,
     * so a walk through it never meets them as links. */
    if (!strncmp(cursor, "self", 4) && (!cursor[4] || cursor[4] == '/')) {
        pid = current_id(__NR_getpid);
        cursor += 4;
    } else if (!strncmp(cursor, "thread-self", 11) && (!cursor[11] || cursor[11] == '/')) {
        pid = current_id(__NR_getpid);
        cursor += 11;
    } else if (*cursor < '1' || *cursor > '9') return FS_LINK_DEFAULT;
    while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    if (*cursor == '/' && !strncmp(cursor, "/task/", 6)) {
        cursor += 6;
        if (*cursor < '0' || *cursor > '9') return FS_LINK_DEFAULT;
        while (*cursor >= '0' && *cursor <= '9') cursor++;
    }
    size_t base = strlen(path);
    if (base + 1 + strlen(component) >= PATH_MAX) return -ENAMETOOLONG;
    int fd = !strcmp(cursor, "/fd");
    if (*cursor && !fd) return FS_LINK_DEFAULT;
    if (!fd && strcmp(component, "exe") && strcmp(component, "cwd") && strcmp(component, "root"))
        return FS_LINK_DEFAULT;
    if (!fd && !strcmp(component, "root")) {
        /* No chroot: the kernel names the host root. Guests share the view's. */
        strcpy(out, "/");
        return FS_LINK_CANONICALIZE;
    }
    if (!fd && !strcmp(component, "exe")) {
        const char *exe = pid == current_id(__NR_getpid) && g_payload_config.exec_exe[0] ?
            g_payload_config.exec_exe : NULL;
        size_t start;
        /* Another loader-run guest names its exe on its own command line. */
        if (!exe && loader_argv(b, pid, &start, &exe) && !exe) {
            const char *target = b->proc_data + start;
            while (target[0] == '.' && target[1] == '/') target += 2;
            if (strlen(target) + 2 < PATH_MAX) {
                out[0] = '/';
                strcpy(out + (target[0] != '/'), target);
                return FS_LINK_CANONICALIZE;
            }
        }
        if (exe && strlen(exe) < PATH_MAX) {
            strcpy(out, exe);
            return FS_LINK_CANONICALIZE;
        }
    }
    strcpy(b->proc_guest, path);
    strcat(b->proc_guest, "/");
    strcat(b->proc_guest, component);
#ifdef GUARDED
    int keep = fd && g_payload_config.guard != GUARD_READS;
#else
    int keep = fd;
#endif
    if (keep) {
        strcpy(out, b->proc_guest);
        return FS_LINK_KEEP;
    }
    int rc = binding_table_map(&b->table, GUEST, b->proc_guest, b->proc_host);
    if (rc < 0) return rc;
    rc = pb_host_readlink(b, b->proc_host, out, PATH_MAX);
    if (rc < 0) return rc;
    if (rc >= PATH_MAX) return -ENAMETOOLONG;
    out[rc] = 0;
    if (out[0] != '/') {
        /* Pipes, sockets and anonymous objects: keep the magic link. */
        strcpy(out, b->proc_guest);
        return FS_LINK_KEEP;
    }
    rc = pb_guest_link_target(b, out);
    return rc < 0 ? rc : FS_LINK_CANONICALIZE;
}

/* /proc/<pid>/cmdline of a loader-run process is served from a memfd with
 * its guest argv; under ptrace PRoot simply shows the real (guest) argv.
 * Returns -ENOENT when the kernel file should be opened instead. */
long pb_proc_cmdline(Bridge *b, int flags)
{
    Comparison c = compare_paths("/proc", b->guest);
    if (c != PATH1_IS_PREFIX) return -ENOENT;
    const char *cursor = b->guest + strlen("/proc/");
    long pid = 0;
    if (*cursor < '1' || *cursor > '9') return -ENOENT;
    while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    if (strcmp(cursor, "/cmdline")) return -ENOENT;
    size_t start;
    const char *exe;
    long length = loader_argv(b, pid, &start, &exe);
    if (!length) return -ENOENT;
    long fd = raw_syscall(__NR_memfd_create, (long)"cmdline",
                          (flags & O_CLOEXEC) ? 1 /* MFD_CLOEXEC */ : 0, 0, 0, 0, 0);
    if (fd < 0) return fd;
    long done = 0, n = 0;
    while (done < length && (n = raw_syscall(__NR_write, fd, (long)b->proc_data + start + done,
                                             length - done, 0, 0, 0)) > 0)
        done += n;
    if (n < 0 || raw_syscall(__NR_lseek, fd, 0, 0, 0, 0, 0) < 0) {
        raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        return n < 0 ? n : -EIO;
    }
    return fd;
}

/* readlink of a canonical /proc path: emulate it like resolution does, then
 * return at most bufsiz bytes without NUL, like the kernel. */
long pb_proc_readlink(Bridge *b, long a[6])
{
    if (!a[2]) return -EFAULT;
    size_t length = strlen(b->guest);
    while (length > 1 && b->guest[length - 1] == '/') b->guest[--length] = 0;
    char *slash = b->guest + length;
    while (slash > b->guest && *slash != '/') slash--;
    *slash = 0;
    const char *component = slash + 1;
    Comparison c = compare_paths("/proc", b->guest);
    int action = pb_proc_link(b, b->cwd, b->guest, component, c);
    if (action < 0) return action;
    long count;
    if (action == FS_LINK_DEFAULT || action == FS_LINK_KEEP) {
        /* Not emulated, or a kept magic link: the kernel's own answer,
         * with an absolute target reported in guest terms. */
        *slash = '/';
        count = pb_host_readlink(b, b->host, b->cwd, sizeof(b->cwd) - 1);
        if (count < 0) return count;
        b->cwd[count] = 0;
        int rc = pb_guest_link_target(b, b->cwd);
        if (rc < 0) return rc;
    }
    count = (long)strlen(b->cwd);
    if ((unsigned long)a[3] < (unsigned long)count) count = (long)a[3];
    memcpy((void *)a[2], b->cwd, (size_t)count);
    return count;
}

/* /proc/<pid>/mounts, mountinfo (and the task/<tid> ones) of a process of
 * this view: generated from the table. -ENOENT: the kernel's file. */
long pb_proc_mounts(Bridge *b, int flags)
{
    if (compare_paths("/proc", b->guest) != PATH1_IS_PREFIX)
        return -ENOENT;
    const char *cursor = b->guest + strlen("/proc/");
    long pid = 0;
    /* A file of its own on HongMeng, a link to self/mounts on Linux. */
    if (!strcmp(cursor, "mounts")) {
        pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        cursor--;
    } else if (!strncmp(cursor, "self/", 5) || !strncmp(cursor, "thread-self/", 12)) {
        pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        cursor = strchr(cursor, '/');
    } else {
        if (*cursor < '1' || *cursor > '9') return -ENOENT;
        while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    }
    if (!strncmp(cursor, "/task/", 6)) {
        cursor += 6;
        if (*cursor < '1' || *cursor > '9') return -ENOENT;
        while (*cursor >= '0' && *cursor <= '9') cursor++;
    }
    int info;
    if (!strcmp(cursor, "/mounts")) info = 0;
    else if (!strcmp(cursor, "/mountinfo")) info = 1;
    else return -ENOENT;
    if (pid != raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0)) {
        size_t start;
        const char *exe;
        if (!loader_argv(b, pid, &start, &exe)) return -ENOENT;
    }
    long fd = raw_syscall(__NR_memfd_create, (long)(info ? "mountinfo" : "mounts"),
                          (flags & O_CLOEXEC) ? 1 /* MFD_CLOEXEC */ : 0, 0, 0, 0, 0);
    if (fd < 0) return fd;
    long rc = mounts_render((int)fd, info);
    if (rc >= 0) rc = raw_syscall(__NR_lseek, fd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        return rc;
    }
    return fd;
}
