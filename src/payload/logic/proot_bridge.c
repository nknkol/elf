/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental path backend. Unmigrated calls retain the legacy backend. */
#include <asm/stat.h>
#include <asm/unistd.h>
#include <linux/fcntl.h>
#include <linux/inotify.h>
#include <linux/un.h>
#ifndef AF_UNIX
#define AF_UNIX 1 /* linux/socket.h does not export address families. */
#endif
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include "config.h"
#include "syscall_nums.h"
#include "proot_bridge.h"
#include "fake_ids.h"
#ifdef FD_EXPERIMENT
#include "fd_experiment.h"
#include "fs_policy.h"
#endif
#include "proot_scratch.h"
#include "path/resolve_core.h"
#include "path/binding_core.h"

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFREG 0100000
#define S_IFLNK 0120000
extern long raw_syscall(long, long, long, long, long, long, long);
_Static_assert(sizeof(struct stat) == 128 && offsetof(struct stat, st_mode) == 16,
               "Adapter requires Linux AArch64 kernel stat ABI");
/* AArch64 user msghdr; only the name fields are rewritten, in a private copy. */
struct guest_msghdr {
    void *name;
    int name_length;
    void *iov;
    size_t iov_length;
    void *control;
    size_t control_length;
    unsigned int flags;
};
_Static_assert(sizeof(struct guest_msghdr) == 56, "AArch64 msghdr ABI");

typedef struct {
    BindingTable table;
    bool mutation;
    bool traverse; /* Final ancestor-only paths are acceptable for this call. */
    bool follow_final; /* Resolution dereferences a final symlink. */
    bool attributes; /* The call changes metadata of an existing name. */
    bool creates; /* The call creates a new name (EEXIST if it exists). */
#ifdef FD_EXPERIMENT
    bool reads; /* Immutable read policy snapshot below is active. */
    enum fs_access access[CONFIG_MAX_BINDS + 1];
    struct fs_policy policy;
    const char *exposed[CONFIG_MAX_BINDS];
    size_t exposed_count;
    /* Private getdents64 bounce: hidden names never reach guest memory. */
    unsigned char dirents[4096];
    char classified[PATH_MAX];
#endif
    const struct proot_path_context *context;
    int anchor_fd;
    struct proot_open_origin anchor;
    PathBinding bindings[CONFIG_MAX_BINDS];
    char cwd[PATH_MAX], guest[PATH_MAX], host[PATH_MAX];
    char first_guest[PATH_MAX], first_host[PATH_MAX];
    struct sockaddr_un address;
    struct guest_msghdr message;
    /* /proc link emulation: never the first_* pair a caller may hold. */
    char proc_guest[PATH_MAX], proc_host[PATH_MAX], proc_link_host[PATH_MAX];
    char proc_data[8192]; /* A loader-run process's kernel cmdline. */
    char proc_candidate[PATH_MAX];
} Bridge;

size_t proot_bridge_scratch_size(void) { return sizeof(Bridge); }

static int host_map(void *opaque, const char *guest, char *host)
{
    Bridge *b = opaque;
    return binding_table_map(&b->table, GUEST, guest, host);
}

#ifdef FD_EXPERIMENT
/* Lexical decision for a canonical guest path, before any host lookup. */
static int path_visibility(Bridge *b, const char *guest)
{
    if (!b->reads) return FS_VISIBLE;
    /* A final "/" or "." keeps directory semantics in PRoot's canonical
     * result; classify the directory itself. */
    size_t length = strnlen(guest, PATH_MAX);
    if (length == PATH_MAX) return -ENAMETOOLONG;
    memcpy(b->classified, guest, length + 1);
    for (;;) {
        if (length > 1 && b->classified[length - 1] == '/') b->classified[--length] = 0;
        else if (length > 2 && !strcmp(b->classified + length - 2, "/."))
            b->classified[length -= 2] = 0;
        else break;
    }
    if (!length || !strcmp(b->classified, "/.")) strcpy(b->classified, "/");
    size_t mount;
    int rc = binding_table_mount_id(&b->table, b->classified, &mount);
    if (rc < 0) return rc;
    return fs_policy_visibility(&b->policy, mount, b->classified, b->exposed, b->exposed_count);
}

/* inotify reports names of a watched directory's direct children. Refuse a
 * watch whose events could name a hidden bind mountpoint (or the host object
 * aliased there); event filtering per watch descriptor is not modeled. */
static int watch_hides_child(Bridge *b, const char *guest)
{
    size_t length = strlen(guest);
    for (size_t i = 0; b->reads && i < b->table.count; i++) {
        const char *child = b->table.entries[i].guest;
        size_t parent = 0;
        for (size_t j = 1; child[j]; j++)
            if (child[j] == '/') parent = j;
        if (!parent) parent = 1; /* Direct child of "/". */
        if (parent != length || strncmp(child, guest, length)) continue;
        int visibility = path_visibility(b, child);
        if (visibility < 0) return visibility;
        if (visibility == FS_HIDDEN) return -EACCES;
    }
    return 0;
}
#endif

/* PRoot "glue": a guest directory that does not exist on the host but leads
 * to a bind destination (component-wise strict ancestor of one). */
static bool glue_ancestor(const Bridge *b, const char *guest)
{
    size_t length = strlen(guest);
    for (size_t i = 0; i < b->table.count; i++) {
        const char *target = b->table.entries[i].guest;
        if (length == 1 && guest[0] == '/') { if (target[1]) return true; continue; }
        if (!strncmp(target, guest, length) && target[length] == '/' && target[length + 1])
            return true;
    }
    return false;
}

/* Glue directories missing from the root are served, like PRoot's glue in
 * its temporary directory, from a private read-only tree that mirrors every
 * bind destination: they can be opened, listed and entered. The tree lives
 * under the glue base (PROOT_TMP_DIR, TMPDIR or /tmp), is named after the
 * user and mount table, is built once and atomically, and is shared by every
 * process of the same view. Nothing is created in the root. */
static char glue_name[PATH_MAX];
static int glue_named, glue_state, glue_scanned;
static unsigned short glue_missing[CONFIG_MAX_BINDS];

static const char *glue_tree(void)
{
    const payload_config_t *cfg = &g_payload_config;
    if (__atomic_load_n(&glue_named, __ATOMIC_ACQUIRE))
        return glue_named > 0 ? glue_name : NULL;
    unsigned long long hash = 0xcbf29ce484222325ULL;
    long uid = raw_syscall(__NR_getuid, 0, 0, 0, 0, 0, 0);
    for (int i = -2; i < cfg->bind_count; i++) {
        const unsigned char *p = (const unsigned char *)(i == -2 ? "" : i == -1 ? cfg->root :
                                                         cfg->binds[i].src);
        for (int pass = 0; pass < 2; pass++) {
            for (; *p; p++) hash = (hash ^ *p) * 0x100000001b3ULL;
            hash = (hash ^ (pass ? 0 : 0xff)) * 0x100000001b3ULL;
            if (i < 0) break;
            p = (const unsigned char *)cfg->binds[i].dst;
        }
    }
    hash = (hash ^ (unsigned long long)uid) * 0x100000001b3ULL;
    size_t length = strlen(cfg->glue_dir);
    int named = -1;
    if (cfg->glue_dir[0] == '/' && length + 32 < PATH_MAX) {
        memcpy(glue_name, cfg->glue_dir, length);
        while (length > 1 && glue_name[length - 1] == '/') length--;
        memcpy(glue_name + length, "/proot-glue-", 12);
        length += 12;
        for (int shift = 60; shift >= 0; shift -= 4)
            glue_name[length++] = "0123456789abcdef"[(hash >> shift) & 15];
        glue_name[length] = 0;
        named = 1;
    }
    __atomic_store_n(&glue_named, named, __ATOMIC_RELEASE);
    return named > 0 ? glue_name : NULL;
}

/* Per bind, the length of its shallowest ancestor missing from the root
 * mount (0 if none), scanned once per process. */
static void glue_scan(Bridge *b)
{
    if (__atomic_load_n(&glue_scanned, __ATOMIC_ACQUIRE)) return;
    for (size_t i = 0; i < b->table.count; i++) {
        const char *dst = b->table.entries[i].guest;
        unsigned short missing = 0;
        for (size_t j = 1; dst[j] && !missing; j++) {
            if (dst[j] != '/') continue;
            memcpy(b->proc_guest, dst, j);
            b->proc_guest[j] = 0;
            size_t mount;
            struct stat st;
            if (binding_table_mount_id(&b->table, b->proc_guest, &mount) < 0 || mount) continue;
            if (host_map(b, b->proc_guest, b->proc_host) < 0) break;
            long ret = raw_syscall(SYS_newfstatat, AT_FDCWD, (long)b->proc_host, (long)&st, 0, 0, 0);
            if (ret == -ENOENT) missing = (unsigned short)j;
        }
        glue_missing[i] = missing;
    }
    __atomic_store_n(&glue_scanned, 1, __ATOMIC_RELEASE);
}

/* Whether the first length bytes of guest name a glue directory missing from
 * the root (a root-mount strict ancestor of a bind below its missing point). */
static bool glue_missing_dir(Bridge *b, const char *guest, size_t length)
{
    if (length <= 1) return false;
    glue_scan(b);
    for (size_t i = 0; i < b->table.count; i++) {
        const char *dst = b->table.entries[i].guest;
        if (glue_missing[i] && length >= glue_missing[i] && !strncmp(dst, guest, length) &&
            dst[length] == '/')
            return true;
    }
    return false;
}

/* Walks the tree's directories of every bind, op 0 creating (mode 0755),
 * 1 sealing (0555), 2 unsealing (0700) top-down, 3 removing bottom-up. */
static int glue_walk(Bridge *b, const char *base, int op)
{
    size_t base_length = strlen(base);
    char *path = b->proc_link_host;
    for (size_t i = 0; i < b->table.count; i++) {
        const char *dst = b->table.entries[i].guest;
        size_t length = strlen(dst);
        if (length <= 1 || base_length + length >= PATH_MAX) continue;
        memcpy(path, base, base_length);
        memcpy(path + base_length, dst, length + 1);
        /* The leaf mirrors the bind source's type. */
        struct stat st;
        bool directory = raw_syscall(SYS_newfstatat, AT_FDCWD, (long)b->table.entries[i].host,
                                     (long)&st, 0, 0, 0) < 0 || (st.st_mode & S_IFMT) == S_IFDIR;
        size_t end = base_length + length;
        for (size_t j = op == 3 ? end : base_length + 1; op == 3 ? j > base_length : j <= end;
             op == 3 ? j-- : j++) {
            if (j != end && path[j] != '/') continue;
            char saved = path[j];
            path[j] = 0;
            bool leaf = j == end;
            long ret = 0;
            if (op == 0) {
                if (leaf && !directory) {
                    ret = raw_syscall(SYS_openat, AT_FDCWD, (long)path,
                                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444, 0, 0);
                    if (ret >= 0) ret = raw_syscall(__NR_close, ret, 0, 0, 0, 0, 0);
                } else {
                    ret = raw_syscall(SYS_mkdirat, AT_FDCWD, (long)path, 0755, 0, 0, 0);
                }
                if (ret == -EEXIST) ret = 0;
            } else if (op == 3) {
                raw_syscall(SYS_unlinkat, AT_FDCWD, (long)path,
                            leaf && !directory ? 0 : AT_REMOVEDIR, 0, 0, 0);
            } else if (!leaf || directory) {
                ret = raw_syscall(SYS_fchmodat, AT_FDCWD, (long)path, op == 1 ? 0555 : 0700, 0, 0, 0);
            }
            path[j] = saved;
            if (ret < 0) return (int)ret;
        }
    }
    return 0;
}

/* A published tree: a directory no one else can write, owned like this
 * process's own creations (some storage ignores modes and assigns a service
 * owner). The bridge itself refuses every mutation inside the tree. */
static bool glue_valid(const char *path, long owner)
{
    struct stat st;
    return !raw_syscall(SYS_newfstatat, AT_FDCWD, (long)path, (long)&st, AT_SYMLINK_NOFOLLOW, 0, 0) &&
           (st.st_mode & S_IFMT) == S_IFDIR && !(st.st_mode & 022) && (long)st.st_uid == owner;
}

static int glue_ready(Bridge *b)
{
    int state = __atomic_load_n(&glue_state, __ATOMIC_ACQUIRE);
    if (state) return state;
    const char *name = glue_tree();
    if (!name) return -1;
    if (glue_valid(name, raw_syscall(__NR_getuid, 0, 0, 0, 0, 0, 0))) {
        __atomic_store_n(&glue_state, 1, __ATOMIC_RELEASE);
        return 1;
    }
    /* Build privately, seal, then publish with one rename; a concurrent
     * builder's identical tree wins instead. */
    char *temp = b->proc_host;
    size_t length = strlen(name);
    if (length + 34 >= PATH_MAX) return -1;
    memcpy(temp, name, length);
    temp[length++] = '.';
    for (int pass = 0; pass < 2; pass++) {
        unsigned long value = (unsigned long)raw_syscall(pass ? __NR_gettid : __NR_getpid,
                                                         0, 0, 0, 0, 0, 0);
        do { temp[length++] = '0' + value % 10; value /= 10; } while (value);
        temp[length++] = pass ? 0 : '.';
    }
    state = -1;
    if (raw_syscall(SYS_mkdirat, AT_FDCWD, (long)temp, 0700, 0, 0, 0) < 0) {
        __atomic_store_n(&glue_state, state, __ATOMIC_RELEASE);
        return state;
    }
    struct stat st;
    long owner = raw_syscall(SYS_newfstatat, AT_FDCWD, (long)temp, (long)&st,
                             AT_SYMLINK_NOFOLLOW, 0, 0) ? -1 : (long)st.st_uid;
    if (glue_valid(name, owner)) {
        raw_syscall(SYS_unlinkat, AT_FDCWD, (long)temp, AT_REMOVEDIR, 0, 0, 0);
        __atomic_store_n(&glue_state, 1, __ATOMIC_RELEASE);
        return 1;
    }
    if (!glue_walk(b, temp, 0) && !glue_walk(b, temp, 1) &&
        !raw_syscall(SYS_fchmodat, AT_FDCWD, (long)temp, 0555, 0, 0, 0)) {
        if (!raw_syscall(SYS_renameat2, AT_FDCWD, (long)temp, AT_FDCWD, (long)name, 0, 0))
            state = 1;
        else if (glue_valid(name, owner))
            state = 1;
    }
    if (glue_valid(temp, owner) || state < 0) {
        /* Unpublished: undo the private copy. */
        raw_syscall(SYS_fchmodat, AT_FDCWD, (long)temp, 0700, 0, 0, 0);
        glue_walk(b, temp, 2);
        glue_walk(b, temp, 3);
        raw_syscall(SYS_unlinkat, AT_FDCWD, (long)temp, AT_REMOVEDIR, 0, 0, 0);
    }
    __atomic_store_n(&glue_state, state, __ATOMIC_RELEASE);
    return state;
}

/* Serves a resolved root-mount guest path that is, or is directly inside, a
 * missing glue directory from the tree. Returns 1 when b->host was replaced. */
static int glue_host(Bridge *b)
{
    if (!b->table.count) return 0;
    size_t length = strlen(b->guest);
    for (;;) {
        if (length > 1 && b->guest[length - 1] == '/') length--;
        else if (length > 2 && b->guest[length - 1] == '.' && b->guest[length - 2] == '/')
            length -= 2;
        else break;
    }
    if (length <= 1) return 0;
    size_t parent = length - 1;
    while (parent && b->guest[parent] != '/') parent--;
    if (!glue_missing_dir(b, b->guest, length) && !glue_missing_dir(b, b->guest, parent))
        return 0;
    size_t mount;
    if (binding_table_mount_id(&b->table, b->guest, &mount) < 0 || mount) return 0;
    if (glue_ready(b) < 0) return 0;
    size_t base = strlen(glue_name), total = strlen(b->guest);
    if (base + total >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(b->host, glue_name, base);
    memcpy(b->host + base, b->guest, total + 1);
    return 1;
}

/* Reverse of glue_host for kernel-reported paths (cwd, FD links). */
static bool glue_guest(const char *host, char *guest)
{
    const char *name = glue_tree();
    if (!name) return false;
    size_t length = strlen(name);
    if (strncmp(host, name, length) || (host[length] && host[length] != '/')) return false;
    strcpy(guest, host[length] ? host + length : "/");
    return true;
}

static int host_lookup(void *opaque, Finality finality, unsigned int depth,
                       const char *guest, char *host)
{
    (void)depth;
#ifdef FD_EXPERIMENT
    /* Every component, base and symlink referee is checked before the host
     * sees it: a hidden name yields EACCES whether or not it exists. */
    int visibility = path_visibility(opaque, guest);
    if (visibility < 0) return visibility;
    if (visibility == FS_HIDDEN) return -EACCES;
#endif
    int rc = host_map(opaque, guest, host);
    if (rc < 0)
        return rc;
    Bridge *b = opaque;
    /* Each host lstat walks the whole host path, which dominates path calls.
     * Skip it where the answer cannot change resolution: a non-followed final
     * name (an existing link stays a link; a missing one is fine), and the
     * root or a bind mount point, whose configured host path the kernel
     * follows itself rather than PRoot reinterpreting it as a guest link. */
    if (finality == FINAL_NORMAL && !b->follow_final)
        return 0;
    if (!strcmp(guest, "/"))
        return 0;
    for (size_t i = 0; i < b->table.count; i++)
        if (!strcmp(guest, b->table.entries[i].guest))
            return 0;
    struct stat st;
    long ret = raw_syscall(SYS_newfstatat, AT_FDCWD, (long)host, (long)&st,
                          AT_SYMLINK_NOFOLLOW, 0, 0);
    /* A missing directory on the way to a bind is glue, not ENOENT. */
    if (ret == -ENOENT && glue_ancestor(b, guest))
        return 0;
    if (ret < 0)
        return IS_FINAL(finality) ? 0 : (int)ret;
    unsigned int type = st.st_mode & S_IFMT;
    if (!IS_FINAL(finality) && type != S_IFDIR && type != S_IFLNK)
        return -ENOTDIR;
    return type == S_IFLNK;
}

static int host_readlink(void *opaque, const char *path, char *out, size_t size)
{
    (void)opaque;
    return (int)raw_syscall(SYS_readlinkat, AT_FDCWD, (long)path, (long)out,
                           size, 0, 0);
}

static int visible_guest_path(Bridge *b, const char *host, char *guest);
static int preferred_guest_path(Bridge *b, const char *host, char *guest);
#ifdef FD_EXPERIMENT
static int path_visibility(Bridge *b, const char *guest);
#endif

/* Kernel /proc links name host objects. An absolute target is reported in
 * guest terms; like PRoot, one outside the view is left unchanged, except
 * under the read guard, which refuses unmappable or hidden objects rather
 * than leaking host names. Non-path targets such as "pipe:[1]" are kept. */
static int guest_link_target(Bridge *b, char *target)
{
    if (target[0] != '/') return 0;
    int guarded = 0;
#ifdef FD_EXPERIMENT
    guarded = g_payload_config.guard_file_reads;
#endif
    int rc = preferred_guest_path(b, target, b->proc_guest);
    if (rc < 0) return guarded ? -EACCES : 0;
#ifdef FD_EXPERIMENT
    rc = path_visibility(b, b->proc_guest);
    if (rc < 0) return rc;
    if (rc == FS_HIDDEN) return -EACCES;
#endif
    strcpy(target, b->proc_guest);
    return 0;
}

static int ordinary_link(void *opaque, char *path, const char *referrer)
{
    Bridge *b = opaque;
    /* Ordinary link contents are guest paths, not host paths to reverse-map.
     * A kernel /proc link (kept as a magic link when final) is traversed
     * here as an intermediate component: its content is a host path. */
    if (binding_table_map(&b->table, GUEST, "/proc", b->proc_link_host) < 0)
        return 0;
    Comparison c = compare_paths(b->proc_link_host, referrer);
    if (c != PATH1_IS_PREFIX) return 0;
    return guest_link_target(b, path);
}

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
    long fd = raw_syscall(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return 0;
    long total = 0, n;
    while (total < (long)sizeof(b->proc_data) &&
           (n = raw_syscall(SYS_read, fd, (long)b->proc_data + total,
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
static int proc_link(void *opaque, char *out, const char *path,
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
    if (*cursor < '1' || *cursor > '9') return FS_LINK_DEFAULT;
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
#ifdef FD_EXPERIMENT
    int keep = fd && !g_payload_config.guard_file_reads;
#else
    int keep = fd;
#endif
    if (keep) {
        strcpy(out, b->proc_guest);
        return FS_LINK_KEEP;
    }
    int rc = binding_table_map(&b->table, GUEST, b->proc_guest, b->proc_host);
    if (rc < 0) return rc;
    rc = host_readlink(b, b->proc_host, out, PATH_MAX);
    if (rc < 0) return rc;
    if (rc >= PATH_MAX) return -ENAMETOOLONG;
    out[rc] = 0;
    if (out[0] != '/') {
        /* Pipes, sockets and anonymous objects: keep the magic link. */
        strcpy(out, b->proc_guest);
        return FS_LINK_KEEP;
    }
    rc = guest_link_target(b, out);
    return rc < 0 ? rc : FS_LINK_CANONICALIZE;
}

/* A reverse name must still denote the same host path after forward mapping.
 * A directory renamed beneath an overmount otherwise silently switches FD
 * identity to the mounted directory. Full retained mount/FD identity is not
 * modeled yet: reject such names rather than traverse a different object. */
static int visible_guest_path(Bridge *b, const char *host, char *guest)
{
    char mapped[PATH_MAX];
    if (glue_guest(host, guest)) return 0;
    int rc = binding_table_map(&b->table, HOST, host, guest);
    if (rc < 0) return rc;
    rc = binding_table_map(&b->table, GUEST, guest, mapped);
    if (rc < 0) return rc;
    return strcmp(host, mapped) ? -EXDEV : 0;
}

static int observed_guest_path(Bridge *b, const char *host, char *guest)
{
    int rc;
    if (glue_guest(host, guest)) return 0;
    /* Reverse through the retained mount, never whichever host alias
     * happens to win the global reverse map. Refuse a moved/overmounted
     * object when this immutable mount can no longer name it faithfully. */
    size_t id = b->anchor.mount_id, mapped_id;
    if (id > b->table.count) return -EXDEV;
    const char *host_prefix = id ? b->table.entries[id-1].host : b->table.root;
    const char *guest_prefix = id ? b->table.entries[id-1].guest : "/";
    Comparison prefix_match = compare_paths(host_prefix, host);
    if (prefix_match != PATHS_ARE_EQUAL && prefix_match != PATH1_IS_PREFIX)
        return -EXDEV;
    strcpy(guest, host);
    rc = binding_replace_core(guest, host_prefix, guest_prefix);
    if (rc < 0) return rc;
    rc = binding_table_mount_id(&b->table, guest, &mapped_id);
    if (rc < 0) return rc;
    if (mapped_id != id) return -EXDEV;
    char mapped[PATH_MAX];
    rc = binding_table_map(&b->table, GUEST, guest, mapped);
    if (rc < 0) return rc;
    return strcmp(host, mapped) ? -EXDEV : 0;
}

/* A host object can have several faithful guest names when a bind's host
 * directory lies inside another mount's host tree. Report it like the
 * kernel/PRoot would: through the most specific mount, never a hidden alias
 * under the read guard. The caller's anchor is preserved. */
static int preferred_guest_path(Bridge *b, const char *host, char *guest)
{
    struct proot_open_origin saved = b->anchor;
    size_t best = 0;
    int found = 0;
    for (size_t id = 0; id <= b->table.count; id++) {
        size_t length = strlen(id ? b->table.entries[id - 1].host : b->table.root);
        if (found && length <= best) continue;
        b->anchor = (struct proot_open_origin){id, true};
        if (observed_guest_path(b, host, b->proc_candidate)) continue;
#ifdef FD_EXPERIMENT
        if (path_visibility(b, b->proc_candidate) == FS_HIDDEN) continue;
#endif
        strcpy(guest, b->proc_candidate);
        best = length;
        found = 1;
    }
    b->anchor = saved;
    return found ? 0 : -EXDEV;
}

static void select_anchor(Bridge *b, int fd)
{
    if (!b->context) return;
    b->anchor_fd = fd;
    b->anchor = (struct proot_open_origin){0, false};
    if (fd == AT_FDCWD) b->anchor = b->context->cwd;
    else for (size_t i = 0; i < 2; i++)
        if (b->context->fd[i] == fd) { b->anchor = b->context->directory[i]; break; }
}

static int host_fd(void *opaque, int fd, char *guest)
{
    Bridge *b = opaque;
    select_anchor(b, fd);
    struct stat st;
    long ret = raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0);
    if (ret < 0)
        return (int)ret;
    if ((st.st_mode & S_IFMT) != S_IFDIR)
        return -ENOTDIR;

    char link[64] = "/proc/self/fd/", digits[16], host[PATH_MAX];
    unsigned int value = (unsigned int)fd;
    size_t count = 0, pos = strlen(link);
    do {
        digits[count++] = '0' + value % 10;
        value /= 10;
    } while (value);
    while (count)
        link[pos++] = digits[--count];
    link[pos] = 0;

    int rc = host_readlink(opaque, link, host, sizeof(host));
    if (rc < 0)
        return rc;
    if (rc >= PATH_MAX)
        return -ENAMETOOLONG;
    host[rc] = 0;
    if (b->anchor.known && fd == b->anchor_fd)
        return observed_guest_path(b, host, guest);
    return visible_guest_path(b, host, guest);
}

static long guest_cwd(Bridge *b)
{
    select_anchor(b, AT_FDCWD);
    long ret = raw_syscall(SYS_getcwd, (long)b->host, sizeof(b->host), 0, 0, 0, 0);
    if (ret < 0)
        return ret;
    if (b->anchor.known && b->anchor_fd == AT_FDCWD)
        return observed_guest_path(b, b->host, b->cwd);
    return visible_guest_path(b, b->host, b->cwd);
}

static int resolve(Bridge *b, int dirfd, const char *path, bool follow)
{
    if (!path)
        return -EFAULT;
    strcpy(b->cwd, "/");
    if (path[0] != '/' && dirfd == AT_FDCWD) {
        long ret = guest_cwd(b);
        if (ret < 0)
            return (int)ret;
    }
    /* Runtime assignments avoid static function-pointer table relocations,
     * which the current ELF payload loader does not apply. */
    PathOps ops;
    ops.lookup = host_lookup;
    ops.readlink = host_readlink;
    ops.detranslate = ordinary_link;
    ops.proc_link = proc_link;
    PathResolver resolver = {{b, &ops}, b->cwd, host_fd, host_map};
    b->follow_final = follow;
    int rc = resolve_path_core(&resolver, dirfd, path, follow, b->guest, b->host);
    if (rc >= 0) {
        int glue = glue_host(b);
        if (glue < 0) return glue;
        /* The tree is shared and read-only, even for its owner or root. A
         * creation over an existing name keeps the kernel's EEXIST. */
        if (glue && b->mutation) {
            struct stat st;
            if (b->attributes) return -EPERM;
            if (!b->creates || raw_syscall(SYS_newfstatat, AT_FDCWD, (long)b->host, (long)&st,
                                           AT_SYMLINK_NOFOLLOW, 0, 0) < 0)
                return -EACCES;
        }
    }
#ifdef FD_EXPERIMENT
    if (rc >= 0 && b->reads) {
        /* ".." skips lookup, so the final name is classified again. */
        int visibility = path_visibility(b, b->guest);
        if (visibility < 0) return visibility;
        if (visibility == FS_HIDDEN || (visibility == FS_TRAVERSE && !b->traverse))
            return -EACCES;
    }
    if (rc >= 0 && b->mutation && g_payload_config.guard_path_mutations) {
        size_t mount;
        rc = binding_table_mount_id(&b->table, b->guest, &mount);
        if (rc < 0) return rc;
        /* Do not turn inferred reverse mappings of imported FDs/cwd into grants. */
        rc = fd_experiment_check_path_mutation(mount, path[0] == '/' || b->anchor.known);
        /* The kernel looks the name up before checking a read-only mount:
         * creating an existing name is EEXIST (mkdir -p walks from "/"). */
        struct stat st;
        if (rc == -EROFS && b->creates &&
            !raw_syscall(SYS_newfstatat, AT_FDCWD, (long)b->host, (long)&st,
                         AT_SYMLINK_NOFOLLOW, 0, 0))
            rc = -EEXIST;
    }
#endif
    return rc;
}

int proot_handles_syscall(long number)
{
    switch (number) {
    case __NR_setxattr: case __NR_lsetxattr:
    case __NR_getxattr: case __NR_lgetxattr:
    case __NR_listxattr: case __NR_llistxattr:
    case __NR_removexattr: case __NR_lremovexattr:
    case __NR_inotify_add_watch:
    case __NR_bind: case __NR_connect: case __NR_sendto: case __NR_sendmsg:
    case SYS_fchmodat:
    case SYS_fchownat:
    case SYS_utimensat:
    case SYS_fchmod:
    case SYS_fchown:
    case SYS_statfs:
    case SYS_fstatfs:
    case SYS_mknodat:
    case __NR_truncate:
    case __NR_ftruncate:
    case SYS_mkdirat:
    case SYS_unlinkat:
    case SYS_symlinkat:
    case SYS_linkat:
    case SYS_renameat:
    case SYS_renameat2:
    case SYS_openat:
    case SYS_newfstatat:
    case SYS_statx:
    case SYS_readlinkat:
    case SYS_chdir:
    case SYS_fchdir:
    case SYS_getcwd:
    case SYS_faccessat:
    case SYS_faccessat2:
        return 1;
    default:
        return 0;
    }
}

/* Moving/deleting configured mountpoints (or their ancestors) would leave
 * the immutable map stale. Refuse until mount relocation is modeled. */
static bool contains_mount(Bridge *b, const char *guest)
{
    if (compare_paths("/", guest) == PATHS_ARE_EQUAL)
        return true;
    for (size_t i = 0; i < b->table.count; i++) {
        Comparison c = compare_paths(guest, b->table.entries[i].guest);
        if (c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX)
            return true;
    }
    return false;
}

/* PRoot fake_id0: a fake root may give files away; the kernel's EPERM for
 * the real user is reported as success (ownership itself is unchanged). */
static long fake_chown(long ret)
{
    return ret == -EPERM && fake_ids_privileged() ? 0 : ret;
}

/* Some storage (HarmonyOS shared storage, Android FUSE) refuses every hard
 * link with EPERM, which breaks dpkg's backups like PRoot without -l. Make
 * the new name a copy of a regular file or symlink instead: same content,
 * mode and times, but not the same inode. Anything else keeps the error. */
static long copy_link(Bridge *b, long error)
{
    struct stat st;
    if (raw_syscall(SYS_newfstatat, AT_FDCWD, (long)b->first_host, (long)&st,
                    AT_SYMLINK_NOFOLLOW, 0, 0) < 0)
        return error;
    if ((st.st_mode & S_IFMT) == S_IFLNK) {
        long n = raw_syscall(SYS_readlinkat, AT_FDCWD, (long)b->first_host,
                             (long)b->proc_data, sizeof(b->proc_data) - 1, 0, 0);
        if (n < 0 || n >= (long)sizeof(b->proc_data) - 1) return error;
        b->proc_data[n] = 0;
        return raw_syscall(SYS_symlinkat, (long)b->proc_data, AT_FDCWD, (long)b->host, 0, 0, 0) < 0 ?
            error : 0;
    }
    if ((st.st_mode & S_IFMT) != S_IFREG) return error;
    long in = raw_syscall(SYS_openat, AT_FDCWD, (long)b->first_host, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (in < 0) return error;
    long out = raw_syscall(SYS_openat, AT_FDCWD, (long)b->host,
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, st.st_mode & 07777, 0, 0);
    long ret = out < 0 ? out : 0;
    while (!ret) {
        long n = raw_syscall(SYS_read, in, (long)b->proc_data, sizeof(b->proc_data), 0, 0, 0);
        if (n <= 0) { ret = n < 0 ? n : 1; break; }
        for (long done = 0; done < n && !ret;) {
            long w = raw_syscall(SYS_write, out, (long)b->proc_data + done, n - done, 0, 0, 0);
            if (w <= 0) ret = w < 0 ? w : -EIO;
            else done += w;
        }
    }
    if (ret == 1) {
        struct { long sec, nsec; } times[2] = {{st.st_atime, st.st_atime_nsec},
                                               {st.st_mtime, st.st_mtime_nsec}};
        raw_syscall(SYS_fchmod, out, st.st_mode & 07777, 0, 0, 0, 0);
        raw_syscall(SYS_utimensat, out, 0, (long)times, 0, 0, 0);
        ret = 0;
    }
    raw_syscall(__NR_close, in, 0, 0, 0, 0, 0);
    if (out >= 0) raw_syscall(__NR_close, out, 0, 0, 0, 0, 0);
    if (ret < 0 && out >= 0) raw_syscall(SYS_unlinkat, AT_FDCWD, (long)b->host, 0, 0, 0, 0);
    /* A name that already exists stays the kernel's answer. */
    return ret < 0 ? (out == -EEXIST ? -EEXIST : error) : 0;
}

static long mutate(Bridge *b, long number, long a[6])
{
    long ret;
    if (number == SYS_symlinkat) {
        if (!a[0])
            return -EFAULT;
        /* The target is opaque link data, NOT a path to resolve or rewrite. */
        ret = resolve(b, (int)a[1], (const char *)a[2], false);
        if (ret < 0)
            return ret;
        return raw_syscall(number, a[0], AT_FDCWD, (long)b->host, 0, 0, 0);
    }
    if (number == SYS_mkdirat || number == SYS_unlinkat) {
        ret = resolve(b, (int)a[0], (const char *)a[1], false);
        if (ret < 0)
            return ret;
        if (number == SYS_unlinkat && contains_mount(b, b->guest))
            return -EBUSY;
        return raw_syscall(number, AT_FDCWD, (long)b->host, a[2], 0, 0, 0);
    }

    bool hardlink = number == SYS_linkat;
    if (hardlink) {
        if (a[4] & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH))
            return -EINVAL;
        if (a[1] && !((const char *)a[1])[0] && (a[4] & AT_EMPTY_PATH))
            return -EOPNOTSUPP; /* Requires source FD mount identity. */
    }
    ret = resolve(b, (int)a[0], (const char *)a[1],
                  hardlink && (a[4] & AT_SYMLINK_FOLLOW));
    if (ret < 0)
        return ret;
    strcpy(b->first_host, b->host);
    strcpy(b->first_guest, b->guest);
    size_t first_mount, second_mount;
    ret = binding_table_mount_id(&b->table, b->first_guest, &first_mount);
    if (ret < 0)
        return ret;
    ret = resolve(b, (int)a[2], (const char *)a[3], false);
    if (ret < 0)
        return ret;
    ret = binding_table_mount_id(&b->table, b->guest, &second_mount);
    if (ret < 0)
        return ret;
    if (!hardlink && (contains_mount(b, b->first_guest) || contains_mount(b, b->guest)))
        return -EBUSY;
    if (first_mount != second_mount)
        return -EXDEV;
    ret = raw_syscall(number, AT_FDCWD, (long)b->first_host,
                      AT_FDCWD, (long)b->host, a[4], 0);
    if (hardlink && ret == -EPERM)
        ret = copy_link(b, ret);
    return ret;
}

static bool path_mutation(long number, long a[6])
{
    switch (number) {
    case SYS_faccessat: case SYS_faccessat2:
        return !!((unsigned int)a[2] & 2); /* W_OK queries mutation permission. */
    case SYS_openat:
        /* O_PATH ignores ordinary access/create/truncate flags. */
        if (a[2] & O_PATH) return false;
        return (a[2] & (O_ACCMODE | O_CREAT | O_TRUNC)) ||
               ((a[2] & O_TMPFILE) == O_TMPFILE);
    case __NR_setxattr: case __NR_lsetxattr:
    case __NR_removexattr: case __NR_lremovexattr:
    case SYS_mknodat: case SYS_mkdirat: case SYS_unlinkat: case SYS_symlinkat:
    case SYS_linkat: case SYS_renameat: case SYS_renameat2:
    case SYS_fchmodat: case SYS_fchownat: case SYS_utimensat: case __NR_truncate:
    case __NR_bind: /* Creates the socket inode at the resolved path. */
        return true;
    default: return false;
    }
}

/* /proc/<pid>/cmdline of a loader-run process is served from a memfd with
 * its guest argv; under ptrace PRoot simply shows the real (guest) argv.
 * Returns -ENOENT when the kernel file should be opened instead. */
static long proc_cmdline(Bridge *b, int flags)
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
    while (done < length && (n = raw_syscall(SYS_write, fd, (long)b->proc_data + start + done,
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
static long proc_readlink(Bridge *b, long a[6])
{
    if (!a[2]) return -EFAULT;
    size_t length = strlen(b->guest);
    while (length > 1 && b->guest[length - 1] == '/') b->guest[--length] = 0;
    char *slash = b->guest + length;
    while (slash > b->guest && *slash != '/') slash--;
    *slash = 0;
    const char *component = slash + 1;
    Comparison c = compare_paths("/proc", b->guest);
    int action = proc_link(b, b->cwd, b->guest, component, c);
    if (action < 0) return action;
    long count;
    if (action == FS_LINK_DEFAULT || action == FS_LINK_KEEP) {
        /* Not emulated, or a kept magic link: the kernel's own answer,
         * with an absolute target reported in guest terms. */
        *slash = '/';
        count = host_readlink(b, b->host, b->cwd, sizeof(b->cwd) - 1);
        if (count < 0) return count;
        b->cwd[count] = 0;
        int rc = guest_link_target(b, b->cwd);
        if (rc < 0) return rc;
    }
    count = (long)strlen(b->cwd);
    if ((unsigned long)a[3] < (unsigned long)count) count = (long)a[3];
    memcpy((void *)a[2], b->cwd, (size_t)count);
    return count;
}

/* Ancestors of exposed binds stay reachable for lookup, listing and cwd only:
 * no content, links, xattrs, watches, execution or namespace changes. */
static bool path_traversal(long number, long a[6])
{
    switch (number) {
    case SYS_newfstatat: case SYS_statx: case SYS_statfs: case SYS_chdir:
        return true;
    case SYS_faccessat: case SYS_faccessat2:
        return !((unsigned int)a[2] & 2);
    case SYS_openat:
        if (a[2] & O_PATH) return true;
        /* O_DIRECTORY makes the kernel refuse a non-directory host object. */
        return (a[2] & O_DIRECTORY) && (a[2] & O_TMPFILE) != O_TMPFILE &&
               !(a[2] & (O_ACCMODE | O_CREAT | O_TRUNC));
    default: return false;
    }
}

/* Translate a pathname AF_UNIX address with guest semantics. bind creates
 * the final name (no follow, mutation policy); connect/sendto/sendmsg reach an
 * existing socket (follow, read visibility). Abstract and non-UNIX addresses,
 * and malformed lengths the kernel will reject, pass through unchanged. A host
 * path longer than sun_path is reached through its parent directory FD. */
static long socket_address(Bridge *b, long number, long a[6])
{
    int sending = number == __NR_sendto, message = number == __NR_sendmsg;
    const void *name;
    unsigned long length;
    if (message) {
        if (!a[1]) return raw_syscall(number, a[0], a[1], a[2], 0, 0, 0);
        memcpy(&b->message, (const void *)a[1], sizeof(b->message));
        name = b->message.name;
        length = (unsigned int)b->message.name_length;
    } else {
        name = (const void *)a[sending ? 4 : 1];
        length = (unsigned int)a[sending ? 5 : 2];
    }
    size_t prefix = offsetof(struct sockaddr_un, sun_path);
    if (!name || length <= prefix || length > sizeof(b->address))
        return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    memset(&b->address, 0, sizeof(b->address));
    memcpy(&b->address, name, length);
    if (b->address.sun_family != AF_UNIX || !b->address.sun_path[0])
        return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    /* Linux accepts an unterminated sun_path filling the given length. */
    char path[sizeof(b->address.sun_path) + 1];
    size_t size = strnlen(b->address.sun_path, length - prefix);
    memcpy(path, b->address.sun_path, size);
    path[size] = 0;
    long ret = resolve(b, AT_FDCWD, path, number != __NR_bind);
    if (ret < 0) return ret;
    long directory = -1;
    size_t host = strlen(b->host);
    memset(&b->address, 0, sizeof(b->address));
    b->address.sun_family = AF_UNIX;
    if (host < sizeof(b->address.sun_path)) {
        memcpy(b->address.sun_path, b->host, host + 1);
    } else {
        size_t slash = host;
        while (slash && b->host[slash - 1] != '/') slash--;
        if (!slash) return -ENAMETOOLONG;
        char *base = b->host + slash;
        b->host[slash - 1] = 0;
        directory = raw_syscall(SYS_openat, AT_FDCWD, (long)(slash == 1 ? "/" : b->host),
                                O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
        if (directory < 0) return directory;
        char *out = b->address.sun_path, *end = out + sizeof(b->address.sun_path) - 1;
        const char *proc = "/proc/self/fd/";
        while (*proc && out < end) *out++ = *proc++;
        char digits[16];
        size_t count = 0;
        unsigned long value = (unsigned long)directory;
        do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
        while (count && out < end) *out++ = digits[--count];
        if (out < end) *out++ = '/';
        size_t left = strlen(base);
        if (count || out + left >= end) {
            raw_syscall(__NR_close, directory, 0, 0, 0, 0, 0);
            return -ENAMETOOLONG;
        }
        memcpy(out, base, left + 1);
    }
    long address_length = (long)(prefix + strlen(b->address.sun_path) + 1);
    if (message) {
        b->message.name = &b->address;
        b->message.name_length = (int)address_length;
        ret = raw_syscall(number, a[0], (long)&b->message, a[2], 0, 0, 0);
    } else if (sending) {
        ret = raw_syscall(number, a[0], a[1], a[2], a[3], (long)&b->address, address_length);
    } else {
        ret = raw_syscall(number, a[0], (long)&b->address, address_length, 0, 0, 0);
    }
    if (directory >= 0) raw_syscall(__NR_close, directory, 0, 0, 0, 0, 0);
    return ret;
}

static long dispatch(Bridge *b, long number, long a[6], struct proot_open_origin *origin)
{
    if(number==SYS_faccessat || number==SYS_faccessat2) {
        /* Match the kernel's int ABI before classifying W_OK. */
        a[2]=(int)a[2];
        if((unsigned int)a[2]&~7u)return -EINVAL;
        if(number==SYS_faccessat2) {
            a[3]=(int)a[3];
            if((unsigned int)a[3]&~(AT_EACCESS|AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH))
                return -EINVAL;
        }
    }
    b->mutation = path_mutation(number, a);
    b->attributes = number == SYS_fchmodat || number == SYS_fchownat ||
        number == SYS_utimensat || number == __NR_truncate || number == __NR_setxattr ||
        number == __NR_lsetxattr || number == __NR_removexattr || number == __NR_lremovexattr;
    b->creates = number == SYS_mkdirat || number == SYS_mknodat || number == SYS_symlinkat ||
        number == __NR_bind;
    b->traverse = path_traversal(number, a);
    if (number == __NR_bind || number == __NR_connect ||
        number == __NR_sendto || number == __NR_sendmsg)
        return socket_address(b, number, a);
    long ret;
    switch (number) {
    case __NR_setxattr: case __NR_getxattr:
    case __NR_listxattr: case __NR_removexattr:
    case __NR_lsetxattr: case __NR_lgetxattr:
    case __NR_llistxattr: case __NR_lremovexattr: {
        /* l* operates on the final symlink itself; intermediate links still
         * resolve normally. Preserve the native name/value/size/flags ABI. */
        bool follow = number != __NR_lsetxattr && number != __NR_lgetxattr &&
                      number != __NR_llistxattr && number != __NR_lremovexattr;
        ret = resolve(b, AT_FDCWD, (const char *)a[0], follow);
        if (ret < 0) return ret;
        return raw_syscall(number, (long)b->host, a[1], a[2], a[3], a[4], a[5]);
    }
    }
    if (number == __NR_inotify_add_watch) {
        if (!a[1]) return -EFAULT;
        ret = resolve(b, AT_FDCWD, (const char *)a[1], !(a[2] & IN_DONT_FOLLOW));
        if (ret < 0) return ret;
#ifdef FD_EXPERIMENT
        ret = watch_hides_child(b, b->guest);
        if (ret < 0) return ret;
#endif
        return raw_syscall(number, a[0], (long)b->host, a[2], 0, 0, 0);
    }
    /* Descriptor operations retain kernel identity; FD policy is a later layer. */
    if (number == SYS_fchown)
        return fake_chown(raw_syscall(number, a[0], a[1], a[2], 0, 0, 0));
    if (number == SYS_fchmod || number == SYS_fstatfs || number == __NR_ftruncate)
        return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (number == SYS_statfs || number == __NR_truncate) {
        if (!a[0]) return -EFAULT;
        ret = resolve(b, AT_FDCWD, (const char *)a[0], true);
        if (ret < 0) return ret;
        return raw_syscall(number, (long)b->host, a[1], a[2], a[3], a[4], a[5]);
    }
    if (number == SYS_fchownat || number == SYS_utimensat) {
        long flags = a[number == SYS_fchownat ? 4 : 3];
        long allowed = AT_SYMLINK_NOFOLLOW;
        if (number == SYS_fchownat) allowed |= AT_EMPTY_PATH;
        if (flags & ~allowed) return -EINVAL;
        /* Linux utimensat(fd, NULL, ...) is an FD operation. */
        if (number == SYS_utimensat && !a[1])
            return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (!a[1]) return -EFAULT;
        const char *path = (const char *)a[1];
        if (!*path && number == SYS_fchownat && (flags & AT_EMPTY_PATH))
            ret = raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        else {
            ret = resolve(b, (int)a[0], path, !(flags & AT_SYMLINK_NOFOLLOW));
            if (ret < 0) return ret;
            ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2], a[3], a[4], a[5]);
        }
        return number == SYS_fchownat ? fake_chown(ret) : ret;
    }
    if (number == SYS_mkdirat || number == SYS_unlinkat || number == SYS_symlinkat ||
        number == SYS_linkat || number == SYS_renameat || number == SYS_renameat2)
        return mutate(b, number, a);
    if (number == SYS_getcwd) {
        ret = guest_cwd(b);
        if (ret < 0)
            return ret;
        size_t size = strlen(b->cwd) + 1;
        if ((unsigned long)a[1] < size)
            return -ERANGE;
        if (!a[0])
            return -EFAULT;
        memcpy((void *)a[0], b->cwd, size);
        /* Raw Linux getcwd returns bytes INCLUDING the NUL terminator. */
        return (long)size;
    }
    if (number == SYS_fchdir) {
        ret = host_fd(b, (int)a[0], b->guest);
        if (ret < 0)
            return ret;
#ifdef FD_EXPERIMENT
        ret = path_visibility(b, b->guest);
        if (ret < 0) return ret;
        if (ret == FS_HIDDEN) return -EACCES;
#endif
        ret = raw_syscall(SYS_fchdir, a[0], 0, 0, 0, 0, 0);
        if (ret >= 0 && origin) *origin = b->anchor;
        return ret;
    }
    if (number == SYS_chdir) {
        ret = resolve(b, AT_FDCWD, (const char *)a[0], true);
        if (ret < 0)
            return ret;
        bool known = origin && (((const char *)a[0])[0] == '/' || b->anchor.known);
        size_t id = 0;
        if (known) {
            ret = binding_table_mount_id(&b->table, b->guest, &id);
            if (ret < 0) return ret;
        }
        ret = raw_syscall(SYS_chdir, (long)b->host, 0, 0, 0, 0, 0);
        if (ret >= 0 && known) *origin = (struct proot_open_origin){id, true};
        return ret;
    }

    const char *path = (const char *)a[1];
    if (!path)
        return -EFAULT;
    bool follow = true;
    if (number == SYS_mknodat) {
        follow = false;
    } else if (number == SYS_openat) {
        int flags = (int)a[2];
        follow = !(flags & O_NOFOLLOW) && !((flags & O_CREAT) && (flags & O_EXCL));
    } else if (number == SYS_readlinkat) {
        follow = false;
        if (a[3] <= 0)
            return -EINVAL;
    } else if (number == SYS_newfstatat || number == SYS_faccessat2 || number == SYS_statx) {
        long flags = number == SYS_statx ? a[2] : a[3];
        follow = !(flags & AT_SYMLINK_NOFOLLOW);
        /* No pathname traversal for AT_EMPTY_PATH; preserve the FD operation
         * and let the kernel validate flags/FD/output, including AT_FDCWD. */
        if (!path[0] && (flags & AT_EMPTY_PATH)) {
            if (number == SYS_newfstatat) {
                if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT))
                    return -EINVAL;
                /* This host's fstatat(empty, symlink-FD) can report the parent
                 * directory unless NOFOLLOW is set. fstat operates on the FD
                 * itself and gives the required symlink identity. */
                if (a[0] != AT_FDCWD)
                    return raw_syscall(__NR_fstat, a[0], a[2], 0, 0, 0, 0);
                return raw_syscall(number, AT_FDCWD, (long)".", a[2],
                                   flags & ~AT_EMPTY_PATH, 0, 0);
            }
            if (number == SYS_statx) {
                /* Empty-path statx likewise refers to the FD itself. */
                return raw_syscall(number, a[0], a[1], flags | AT_SYMLINK_NOFOLLOW,
                                   a[3], a[4], a[5]);
            }
            return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        }
    }
    /* readlinkat supports an empty pathname on an O_PATH symlink FD. */
    if (number == SYS_readlinkat && !path[0])
        return raw_syscall(number, a[0], a[1], a[2], a[3], 0, 0);

    bool observed_open = number == SYS_openat && origin &&
        (path[0] == '/' || b->anchor.known);
    ret = resolve(b, (int)a[0], path, follow);
    if (ret < 0)
        return ret;
    if (number == SYS_readlinkat) {
        Comparison c = compare_paths("/proc", b->guest);
        if (c == PATH1_IS_PREFIX)
            return proc_readlink(b, a);
        /* Preserve ordinary symlink bytes. Kernel handles truncation, no NUL
         * and invalid output addresses. Do not rewrite a relative target. */
    }
    size_t mount_id = 0;
    if (observed_open) {
        ret = binding_table_mount_id(&b->table, b->guest, &mount_id);
        if (ret < 0) return ret;
    }
    /* Without a glue tree (no writable glue base), metadata of a glue
     * directory is still a directory's: the root's. */
    if ((number == SYS_newfstatat || number == SYS_statx || number == SYS_faccessat ||
         number == SYS_faccessat2) && glue_ancestor(b, b->guest)) {
        struct stat probe;
        if (raw_syscall(SYS_newfstatat, AT_FDCWD, (long)b->host, (long)&probe,
                        AT_SYMLINK_NOFOLLOW, 0, 0) == -ENOENT)
            strcpy(b->host, b->table.root);
    }
    if (number == SYS_openat && !(a[2] & (O_ACCMODE | O_PATH | O_CREAT)))
        ret = proc_cmdline(b, (int)a[2]);
    else ret = -ENOENT;
    if (ret == -ENOENT)
        ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2], a[3], a[4], a[5]);
    if (ret >= 0 && observed_open)
        *origin = (struct proot_open_origin){mount_id, true};
    return ret;
}

/* A few per-process bridges avoid mmap/munmap and page faults on every path
 * call. Slots are claimed atomically, so threads share them safely; every
 * bridge is released before any call that does not return (exec runs from
 * its own scratch). An experimental vfork child keeps its reserved scratch. */
#define BRIDGE_POOL 4
static Bridge *bridge_pool[BRIDGE_POOL];
static int bridge_used[BRIDGE_POOL];
static long bridge_acquire(void)
{
#ifdef FD_EXPERIMENT
    if (!fd_experiment_shared_scratch()) return proot_scratch_alloc(sizeof(Bridge));
#endif
    for (int i = 0; i < BRIDGE_POOL; i++) {
        int free_slot = 0;
        if (!__atomic_compare_exchange_n(&bridge_used[i], &free_slot, 1, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            continue;
        Bridge *b = __atomic_load_n(&bridge_pool[i], __ATOMIC_ACQUIRE);
        if (!b) {
            long mem = proot_scratch_alloc(sizeof(Bridge));
            if ((unsigned long)mem >= (unsigned long)-4095) {
                __atomic_store_n(&bridge_used[i], 0, __ATOMIC_RELEASE);
                return mem;
            }
            b = (void *)mem;
            __atomic_store_n(&bridge_pool[i], b, __ATOMIC_RELEASE);
        }
        return (long)b;
    }
    return proot_scratch_alloc(sizeof(Bridge));
}
static void bridge_release(Bridge *b)
{
    for (int i = 0; i < BRIDGE_POOL; i++)
        if (__atomic_load_n(&bridge_pool[i], __ATOMIC_ACQUIRE) == b) {
            __atomic_store_n(&bridge_used[i], 0, __ATOMIC_RELEASE);
            return;
        }
    proot_scratch_free(b, sizeof(Bridge));
}

static long bridge_create(Bridge **out)
{
    payload_config_t *cfg = &g_payload_config;
    if (cfg->overlay_count || cfg->vfs_lower[0] || cfg->vfs_upper[0])
        return -EOPNOTSUPP;
    if (cfg->bind_count < 0 || cfg->bind_count > CONFIG_MAX_BINDS)
        return -EINVAL;
    long mem = bridge_acquire();
    if ((unsigned long)mem >= (unsigned long)-4095)
        return mem;
    Bridge *b = (void *)mem;
    b->context = NULL;
    b->follow_final = true;
    b->mutation = false;
    b->attributes = false;
    b->creates = false;
    b->traverse = false;
    b->anchor_fd = AT_FDCWD;
    b->anchor = (struct proot_open_origin){0, false};
    b->table = (BindingTable){cfg->root[0] ? cfg->root : "/", b->bindings,
                             (size_t)cfg->bind_count};
    for (int i = 0; i < cfg->bind_count; i++)
        b->bindings[i] = (PathBinding){cfg->binds[i].src, cfg->binds[i].dst};
    long ret = binding_table_validate(&b->table);
#ifdef FD_EXPERIMENT
    b->reads = false;
    if (ret >= 0 && cfg->guard_file_reads) {
        size_t count;
        ret = fd_experiment_mount_access(b->access, &count);
        b->policy = (struct fs_policy){b->access, count};
        b->exposed_count = 0;
        for (size_t i = 0; ret >= 0 && i < b->table.count; i++) {
            size_t id;
            ret = binding_table_mount_id(&b->table, b->bindings[i].guest, &id);
            /* Shadowed duplicate destinations expose nothing. */
            if (ret >= 0 && id == i + 1 && b->access[id] != FS_DENY)
                b->exposed[b->exposed_count++] = b->bindings[i].guest;
        }
        b->reads = ret >= 0;
    }
#endif
    if (ret < 0) {
        bridge_release(b);
        return ret;
    }
    *out = b;
    return 0;
}

/* Exactly one retained mount must faithfully name this host path. Under the
 * read guard a hidden name cannot reach the object, so it is not a competing
 * view; two visible aliases (e.g. ro and rw) remain ambiguous. */
static int unique_mount(Bridge *b, const char *host, size_t *selected)
{
    size_t matches=0;
    /* The glue tree belongs to the root mount alone. */
    if(glue_guest(host,b->guest)) {
#ifdef FD_EXPERIMENT
        int visibility=path_visibility(b,b->guest);
        if(visibility<0)return visibility;
        if(visibility==FS_HIDDEN)return -EXDEV;
#endif
        *selected=0;return 0;
    }
    for(size_t id=0;id<=b->table.count;id++) {
        b->anchor=(struct proot_open_origin){id,true};
        if(observed_guest_path(b,host,b->guest))continue;
#ifdef FD_EXPERIMENT
        int visibility=path_visibility(b,b->guest);
        if(visibility<0)return visibility;
        if(visibility==FS_HIDDEN)continue;
#endif
        *selected=id;matches++;
    }
    return matches==1 ? 0 : -EXDEV;
}

int proot_fd_guest_path(int fd, char *guest, size_t capacity)
{
    if (!guest || !capacity) return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return (int)ret;
    char link[32];
    strcpy(link, "/proc/self/fd/");
    size_t at = strlen(link);
    unsigned value = (unsigned)fd;
    char digits[16];
    int count = 0;
    do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) link[at++] = digits[--count];
    link[at] = 0;
    ret = host_readlink(b, link, b->proc_host, sizeof(b->proc_host) - 1);
    if (ret >= 0) {
        b->proc_host[ret] = 0;
        size_t length = (size_t)ret;
        /* Deleted files, memfds and other non-path objects have no guest name. */
        if (b->proc_host[0] != '/' ||
            (length >= 10 && !strcmp(b->proc_host + length - 10, " (deleted)")))
            ret = -EOPNOTSUPP;
        else if (preferred_guest_path(b, b->proc_host, b->proc_guest) < 0)
            ret = -EACCES;
        else if (strlen(b->proc_guest) >= capacity)
            ret = -ENAMETOOLONG;
        else {
            strcpy(guest, b->proc_guest);
            ret = 0;
        }
    }
    bridge_release(b);
    return (int)ret;
}

void proot_socket_name(long number, long fd, void *address, unsigned *length,
                       unsigned capacity)
{
    size_t prefix = offsetof(struct sockaddr_un, sun_path);
    if (!address || !length || *length <= prefix + 1 || *length > sizeof(struct sockaddr_un))
        return; /* Unnamed or not a pathname address: nothing to rewrite. */
    Bridge *b;
    if (bridge_create(&b) < 0) return;
    if (*length > capacity) {
        /* The guest buffer holds a truncated host name: query it privately.
         * accept reports the peer, so ask the new connection for its peer. */
        unsigned full = sizeof(b->address);
        long query = number == __NR_getsockname ? __NR_getsockname : __NR_getpeername;
        if (raw_syscall(query, fd, (long)&b->address, (long)&full, 0, 0, 0) < 0 ||
            full != *length) {
            bridge_release(b);
            return;
        }
    } else memcpy(&b->address, address, *length);
    if (b->address.sun_family == AF_UNIX && b->address.sun_path[0]) {
        size_t size = strnlen(b->address.sun_path, *length - prefix);
        memcpy(b->proc_host, b->address.sun_path, size);
        b->proc_host[size] = 0;
        int rc = preferred_guest_path(b, b->proc_host, b->proc_guest);
#ifdef FD_EXPERIMENT
        if (rc < 0 && g_payload_config.guard_file_reads) {
            *length = (unsigned)sizeof(b->address.sun_family);
            bridge_release(b);
            return;
        }
#endif
        size_t guest = strlen(b->proc_guest);
        if (!rc && guest < sizeof(b->address.sun_path)) {
            memset(b->address.sun_path, 0, sizeof(b->address.sun_path));
            memcpy(b->address.sun_path, b->proc_guest, guest + 1);
            unsigned full = (unsigned)(prefix + guest + 1);
            memcpy(address, &b->address, full < capacity ? full : capacity);
            *length = full;
        }
    }
    bridge_release(b);
}

int proot_revalidate_cwd(struct proot_open_origin *origin)
{
    if(!origin)return -EINVAL;
    *origin=(struct proot_open_origin){0,false};
    Bridge *b;
    long ret=bridge_create(&b);if(ret<0)return ret;
    ret=raw_syscall(SYS_getcwd,(long)b->first_host,sizeof(b->first_host),0,0,0,0);
    if(ret>=0) {
        size_t selected;
        /* Unreachable or ambiguous (aliased) directories stay unknown. */
        ret=unique_mount(b,b->first_host,&selected);
        if(!ret)*origin=(struct proot_open_origin){selected,true};
    }
    bridge_release(b);return (int)ret;
}

int proot_revalidate_regular_fd(int fd, struct proot_open_origin *origin)
{
    if(!origin)return -EINVAL;
    *origin=(struct proot_open_origin){0,false};
    struct stat live, named, again;
    long ret=raw_syscall(__NR_fstat,fd,(long)&live,0,0,0,0);
    if(ret<0)return ret;
    if((live.st_mode&S_IFMT)!=S_IFREG || !live.st_nlink)return -EOPNOTSUPP;
    Bridge *b;
    ret=bridge_create(&b);if(ret<0)return ret;
    char link[64]="/proc/self/fd/",digits[16];
    unsigned value=(unsigned)fd;size_t count=0,pos=strlen(link);
    do { digits[count++]='0'+value%10;value/=10; } while(value);
    while(count)link[pos++]=digits[--count];link[pos]=0;
    ret=host_readlink(b,link,b->first_host,sizeof(b->first_host));
    if(ret<0)goto done;
    if(ret>=PATH_MAX) { ret=-ENAMETOOLONG;goto done; }
    b->first_host[ret]=0;
    if(!ret || b->first_host[0]!='/' ||
       (ret>=10 && !strcmp(b->first_host+ret-10," (deleted)"))) {
        ret=-EXDEV;goto done;
    }
    ret=raw_syscall(__NR_newfstatat,AT_FDCWD,(long)b->first_host,(long)&named,
                    AT_SYMLINK_NOFOLLOW,0,0);
    if(ret<0)goto done;
    if((named.st_mode&S_IFMT)!=S_IFREG || named.st_dev!=live.st_dev || named.st_ino!=live.st_ino) {
        ret=-ESTALE;goto done;
    }
    size_t selected;
    ret=unique_mount(b,b->first_host,&selected);
    if(ret<0)goto done;
    ret=raw_syscall(__NR_fstat,fd,(long)&again,0,0,0,0);
    if(ret<0)goto done;
    if(again.st_dev!=live.st_dev || again.st_ino!=live.st_ino || !again.st_nlink) {
        ret=-ESTALE;goto done;
    }
    *origin=(struct proot_open_origin){selected,true};ret=0;
 done:
    bridge_release(b);return ret;
}

#ifdef FD_EXPERIMENT
/* Kernel getdents64 record: ino, next offset, reclen, type, NUL-terminated name. */
#define DIRENT_OFFSET 8
#define DIRENT_RECLEN 16
#define DIRENT_NAME 19
long proot_getdents_visible(int fd, void *buffer, unsigned long count,
                            const struct proot_open_origin *anchor)
{
    if (!anchor) return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return ret;
    b->anchor = *anchor;
    b->anchor_fd = fd;
    ret = host_fd(b, fd, b->first_guest);
    if (ret == -ENOTDIR) {
        /* Not a directory: the kernel reports its own error, no names. */
        ret = raw_syscall(__NR_getdents64, fd, (long)buffer, (long)count, 0, 0, 0);
        goto done;
    }
    /* A directory without a faithful guest name cannot be filtered. */
    if (ret == -EXDEV) ret = -EACCES;
    if (ret < 0) goto done;
    ret = path_visibility(b, b->first_guest);
    if (ret == FS_HIDDEN) ret = -EACCES;
    if (ret < 0) goto done;
    if (!buffer) { ret = -EFAULT; goto done; }
    size_t base = strlen(b->first_guest);
    for (;;) {
        /* Read a full private batch so a hidden record never makes a small
         * guest buffer fail. Visible records are copied out while they fit;
         * the directory cursor is then moved back to the first record not
         * returned. Hidden names never touch guest memory, a batch hiding
         * every entry is retried, and zero still means end of directory. */
        long position = raw_syscall(__NR_lseek, fd, 0, 1 /* SEEK_CUR */, 0, 0, 0);
        if (position < 0) { ret = position; goto done; }
        ret = raw_syscall(__NR_getdents64, fd, (long)b->dirents, sizeof(b->dirents), 0, 0, 0);
        if (ret <= 0) goto done;
        unsigned char *bytes = b->dirents;
        size_t kept = 0;
        for (size_t offset = 0; offset < (size_t)ret;) {
            unsigned short length;
            long next;
            memcpy(&length, bytes + offset + DIRENT_RECLEN, sizeof(length));
            if (length < DIRENT_NAME + 1 || offset + length > (size_t)ret) { ret = -EIO; goto done; }
            memcpy(&next, bytes + offset + DIRENT_OFFSET, sizeof(next));
            const char *name = (const char *)bytes + offset + DIRENT_NAME;
            bool keep = !strcmp(name, ".") || !strcmp(name, "..");
            if (!keep) {
                size_t size = strnlen(name, length - DIRENT_NAME);
                if (base + 1 + size >= PATH_MAX) { ret = -ENAMETOOLONG; goto done; }
                memcpy(b->guest, b->first_guest, base);
                size_t at = base;
                if (base != 1) b->guest[at++] = '/';
                memcpy(b->guest + at, name, size);
                b->guest[at + size] = 0;
                int visibility = path_visibility(b, b->guest);
                if (visibility < 0) { ret = visibility; goto done; }
                keep = visibility != FS_HIDDEN;
            }
            if (keep) {
                if (kept + length > count) {
                    /* Like the kernel: the record stays for the next call,
                     * and a first visible record that cannot fit is EINVAL. */
                    long sought = raw_syscall(__NR_lseek, fd, position, 0 /* SEEK_SET */, 0, 0, 0);
                    ret = sought < 0 ? sought : kept ? (long)kept : -EINVAL;
                    goto done;
                }
                memcpy((unsigned char *)buffer + kept, bytes + offset, length);
                kept += length;
            }
            position = next;
            offset += length;
        }
        if (kept) { ret = (long)kept; goto done; }
    }
done:
    bridge_release(b);
    return ret;
}
#endif

static long bridge_syscall(long number, long args[6], const struct proot_open_origin *anchor,
                           struct proot_open_origin *origin)
{
    if (!proot_handles_syscall(number))
        return -ENOSYS;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0)
        return ret;
    if (anchor) {
        b->anchor = *anchor;
        b->anchor_fd = (number == SYS_chdir || number == SYS_getcwd) ? AT_FDCWD : (int)args[0];
    }
    ret = dispatch(b, number, args, origin);
    bridge_release(b);
    return ret;
}

long proot_syscall(long number, long args[6])
{
    return bridge_syscall(number, args, NULL, NULL);
}

long proot_openat(long args[6], const struct proot_open_origin *anchor,
                  struct proot_open_origin *origin)
{
    if (!origin) return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    return bridge_syscall(SYS_openat, args, anchor, origin);
}

long proot_cwd(long number, long args[6], const struct proot_open_origin *anchor,
               struct proot_open_origin *origin)
{
    if (!origin || (number != SYS_chdir && number != SYS_fchdir && number != SYS_getcwd))
        return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    return bridge_syscall(number, args, anchor, origin);
}

long proot_context_syscall(long number, long args[6], const struct proot_path_context *context)
{
    if (!context || !proot_handles_syscall(number)) return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return ret;
    b->context = context;
    ret = dispatch(b, number, args, NULL);
    bridge_release(b);
    return ret;
}

int proot_resolve_exec_path(int dirfd, const char *path, bool follow,
                            char *guest, char *host, size_t capacity,
                            const struct proot_path_context *context)
{
    if (!guest || !host || !capacity)
        return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0)
        return (int)ret;
    b->context = context;
    ret = resolve(b, dirfd, path, follow);
    if (!ret) {
        if (strlen(b->guest) >= capacity || strlen(b->host) >= capacity)
            ret = -ENAMETOOLONG;
        else {
            strcpy(guest, b->guest);
            strcpy(host, b->host);
        }
    }
    bridge_release(b);
    return (int)ret;
}

/* This deliberately does not emulate general openat2 resolution. Holding the
 * directory FD and opening one non-followed component keeps the actual lookup
 * in the kernel; canonicalizing then opening an absolute path would lose the
 * BENEATH constraint. Cross-bind targets require retained mount identities. */
long proot_open_beneath(int dirfd, const char *path, unsigned long flags,
                       const struct proot_open_origin *hint, struct proot_open_origin *origin)
{
    if (!origin) return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    if (!path) return -EFAULT;
    char name[PATH_MAX];
    size_t length = strnlen(path, sizeof(name));
    if (length == sizeof(name)) return -ENAMETOOLONG;
    memcpy(name, path, length + 1);
    if (!length) return -ENOENT;
    if (name[0] == '/' || !strcmp(name, "..")) return -EXDEV;
    /* Trailing separators require directory resolution. Only accept them
     * with explicit O_DIRECTORY; keep NOFOLLOW at the actual kernel lookup.
     * Following a trailing symlink is outside this restricted subset. */
    int trailing = name[length - 1] == '/';
    if (trailing) {
        if (!(flags & O_DIRECTORY)) return -EOPNOTSUPP;
        while (length && name[length - 1] == '/') name[--length] = 0;
        if (!strcmp(name, "..")) return -EXDEV;
    }
    if (strchr(name, '/')) return -EOPNOTSUPP;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return ret;
    long anchor = dirfd;
    if (dirfd == AT_FDCWD) {
        anchor = raw_syscall(SYS_openat, AT_FDCWD, (long)".",
                             O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
        if (anchor < 0) { ret = anchor; goto out; }
    }
    if (hint) { b->anchor = *hint; b->anchor_fd = (int)anchor; }
    b->traverse = true; /* This subset always opens O_PATH. */
    ret = host_fd(b, (int)anchor, b->first_guest);
    if (ret < 0) goto close_anchor;
    size_t base_mount, target_mount;
    ret = binding_table_mount_id(&b->table, b->first_guest, &base_mount);
    if (ret < 0) goto close_anchor;
    ret = resolve(b, (int)anchor, name, false);
    if (ret < 0) goto close_anchor;
    ret = binding_table_mount_id(&b->table, b->guest, &target_mount);
    if (ret < 0) goto close_anchor;
    if (base_mount != target_mount) { ret = -EOPNOTSUPP; goto close_anchor; }
    ret = raw_syscall(SYS_openat, anchor, (long)name, flags, 0, 0, 0);
    if (trailing && ret == -ENOTDIR) ret = -EOPNOTSUPP;
    if (ret >= 0 && b->anchor.known)
        *origin = (struct proot_open_origin){target_mount, true};
close_anchor:
    if (dirfd == AT_FDCWD) raw_syscall(__NR_close, anchor, 0, 0, 0, 0, 0);
out:
    bridge_release(b);
    return ret;
}
