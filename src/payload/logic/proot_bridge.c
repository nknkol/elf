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
#include "proot_scratch.h"
#include "path/resolve_core.h"
#include "path/binding_core.h"

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFLNK 0120000
extern long raw_syscall(long, long, long, long, long, long, long);
_Static_assert(sizeof(struct stat) == 128 && offsetof(struct stat, st_mode) == 16,
               "Adapter requires Linux AArch64 kernel stat ABI");

typedef struct {
    BindingTable table;
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

static int host_lookup(void *opaque, Finality finality, unsigned int depth,
                       const char *guest, char *host)
{
    (void)depth;
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

static int host_fd(void *opaque, int fd, char *guest)
{
    Bridge *b = opaque;
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
    return visible_guest_path(b, host, guest);
}

static long guest_cwd(Bridge *b)
{
    long ret = raw_syscall(SYS_getcwd, (long)b->host, sizeof(b->host), 0, 0, 0, 0);
    if (ret < 0)
        return ret;
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
    return resolve_path_core(&resolver, dirfd, path, follow, b->guest, b->host);
}

int proot_handles_syscall(long number)
{
    switch (number) {
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

static long dispatch(Bridge *b, long number, long a[6])
{
    long ret;
    if (number == __NR_inotify_add_watch) {
        if (!a[1]) return -EFAULT;
        ret = resolve(b, AT_FDCWD, (const char *)a[1], !(a[2] & IN_DONT_FOLLOW));
        if (ret < 0) return ret;
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
        return raw_syscall(SYS_fchdir, a[0], 0, 0, 0, 0, 0);
    }
    if (number == SYS_chdir) {
        ret = resolve(b, AT_FDCWD, (const char *)a[0], true);
        if (ret < 0)
            return ret;
        return raw_syscall(SYS_chdir, (long)b->host, 0, 0, 0, 0, 0);
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
    return raw_syscall(number, AT_FDCWD, (long)b->host, a[2], a[3], a[4], a[5]);
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
    b->table = (BindingTable){cfg->root[0] ? cfg->root : "/", b->bindings,
                             (size_t)cfg->bind_count};
    for (int i = 0; i < cfg->bind_count; i++)
        b->bindings[i] = (PathBinding){cfg->binds[i].src, cfg->binds[i].dst};
    long ret = binding_table_validate(&b->table);
    if (ret < 0) {
        proot_scratch_free((void *)mem,sizeof(Bridge));
        return ret;
    }
    *out = b;
    return 0;
}

long proot_syscall(long number, long args[6])
{
    if (!proot_handles_syscall(number))
        return -ENOSYS;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0)
        return ret;
    ret = dispatch(b, number, args);
    proot_scratch_free(b,sizeof(Bridge));
    return ret;
}

int proot_resolve_exec_path(int dirfd, const char *path, bool follow,
                            char *guest, char *host, size_t capacity)
{
    if (!guest || !host || !capacity)
        return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0)
        return (int)ret;
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
