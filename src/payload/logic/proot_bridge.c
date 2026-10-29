/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Experimental path backend. Unmigrated calls retain the legacy backend. */
#include <asm/stat.h>
#include <asm/unistd.h>
#include <linux/fcntl.h>
#include <linux/inotify.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include "config.h"
#include "syscall_nums.h"
#include "proot_bridge.h"
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

typedef struct {
    BindingTable table;
    bool mutation;
    bool traverse; /* Final ancestor-only paths are acceptable for this call. */
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
    struct stat st;
    long ret = raw_syscall(SYS_newfstatat, AT_FDCWD, (long)host, (long)&st,
                          AT_SYMLINK_NOFOLLOW, 0, 0);
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

static int ordinary_link(void *opaque, char *path, const char *referrer)
{
    (void)opaque;
    (void)path;
    (void)referrer;
    /* Ordinary link contents are guest paths, not host paths to reverse-map. */
    return 0;
}

static int proc_link(void *opaque, char *out, const char *path,
                     const char *component, Comparison comparison)
{
    (void)opaque;
    (void)out;
    (void)path;
    (void)component;
    (void)comparison;
    return -EOPNOTSUPP;
}

/* A reverse name must still denote the same host path after forward mapping.
 * A directory renamed beneath an overmount otherwise silently switches FD
 * identity to the mounted directory. Full retained mount/FD identity is not
 * modeled yet: reject such names rather than traverse a different object. */
static int visible_guest_path(Bridge *b, const char *host, char *guest)
{
    char mapped[PATH_MAX];
    int rc = binding_table_map(&b->table, HOST, host, guest);
    if (rc < 0) return rc;
    rc = binding_table_map(&b->table, GUEST, guest, mapped);
    if (rc < 0) return rc;
    return strcmp(host, mapped) ? -EXDEV : 0;
}

static int observed_guest_path(Bridge *b, const char *host, char *guest)
{
    int rc;
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
    int rc = resolve_path_core(&resolver, dirfd, path, follow, b->guest, b->host);
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
    return raw_syscall(number, AT_FDCWD, (long)b->first_host,
                       AT_FDCWD, (long)b->host, a[4], 0);
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
        return true;
    default: return false;
    }
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
    b->traverse = path_traversal(number, a);
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
    if (number == SYS_fchmod || number == SYS_fchown ||
        number == SYS_fstatfs || number == __NR_ftruncate)
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
            return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        ret = resolve(b, (int)a[0], path, !(flags & AT_SYMLINK_NOFOLLOW));
        if (ret < 0) return ret;
        return raw_syscall(number, AT_FDCWD, (long)b->host, a[2], a[3], a[4], a[5]);
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
        if (c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX)
            return -EOPNOTSUPP;
        /* Preserve ordinary symlink bytes. Kernel handles truncation, no NUL
         * and invalid output addresses. Do not rewrite a relative target. */
    }
    size_t mount_id = 0;
    if (observed_open) {
        ret = binding_table_mount_id(&b->table, b->guest, &mount_id);
        if (ret < 0) return ret;
    }
    ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2], a[3], a[4], a[5]);
    if (ret >= 0 && observed_open)
        *origin = (struct proot_open_origin){mount_id, true};
    return ret;
}

static long bridge_create(Bridge **out)
{
    payload_config_t *cfg = &g_payload_config;
    if (cfg->overlay_count || cfg->vfs_lower[0] || cfg->vfs_upper[0])
        return -EOPNOTSUPP;
    if (cfg->bind_count < 0 || cfg->bind_count > CONFIG_MAX_BINDS)
        return -EINVAL;
    long mem = proot_scratch_alloc(sizeof(Bridge));
    if ((unsigned long)mem >= (unsigned long)-4095)
        return mem;
    Bridge *b = (void *)mem;
    b->context = NULL;
    b->mutation = false;
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
        proot_scratch_free((void *)mem,sizeof(Bridge));
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
    proot_scratch_free(b,sizeof(Bridge));return (int)ret;
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
    proot_scratch_free(b,sizeof(Bridge));return ret;
}

#ifdef FD_EXPERIMENT
/* Kernel getdents64 record: ino, off, reclen, type, NUL-terminated name. */
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
    /* A smaller kernel count only returns fewer records; tiny guest counts
     * still get the kernel's own EINVAL. */
    unsigned long bounce = count < sizeof(b->dirents) ? count : sizeof(b->dirents);
    for (;;) {
        /* The kernel fills the private bounce and advances the offset; only
         * visible records are copied out, so hidden names never touch guest
         * memory, even transiently. A batch hiding every entry is retried,
         * so zero still means end of directory. */
        ret = raw_syscall(__NR_getdents64, fd, (long)b->dirents, (long)bounce, 0, 0, 0);
        if (ret <= 0) goto done;
        unsigned char *bytes = b->dirents;
        size_t kept = 0;
        for (size_t offset = 0; offset < (size_t)ret;) {
            unsigned short length;
            memcpy(&length, bytes + offset + DIRENT_RECLEN, sizeof(length));
            if (length < DIRENT_NAME + 1 || offset + length > (size_t)ret) { ret = -EIO; goto done; }
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
                if (kept != offset) memmove(bytes + kept, bytes + offset, length);
                kept += length;
            }
            offset += length;
        }
        if (kept) {
            memcpy(buffer, bytes, kept);
            ret = (long)kept;
            goto done;
        }
    }
done:
    proot_scratch_free(b, sizeof(Bridge));
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
    proot_scratch_free(b,sizeof(Bridge));
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
    proot_scratch_free(b, sizeof(Bridge));
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
    proot_scratch_free(b,sizeof(Bridge));
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
    proot_scratch_free(b, sizeof(Bridge));
    return ret;
}
