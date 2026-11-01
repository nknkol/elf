/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PRoot path backend, mounts: the R4 mount table (mount, umount2), tmpfs,
 * R6 overlay and emulated loop devices, /proc/filesystems. */
#include "proot_bridge_internal.h"

/* ---- R4: mount, umount2 and the /proc mount tables (docs/OCI.md) ----
 * A mount changes the shared table every process of the container reads
 * into its binding table; nothing is mounted in the kernel. */
#define MS_RDONLY_ 1ul
#define MS_NOSUID_ 2ul
#define MS_NODEV_ 4ul
#define MS_NOEXEC_ 8ul
#define MS_REMOUNT_ 32ul
#define MS_BIND_ 4096ul
#define MS_MOVE_ 8192ul
#define MS_REC_ 16384ul
#define MS_PROPAGATION_ ((1ul << 17) | (1ul << 18) | (1ul << 19) | (1ul << 20))
#define MS_MGC_MSK_ 0xffff0000ul
#define MS_MGC_VAL_ 0xc0ed0000ul

/* Filesystems shown from the host's own directory. */
static const struct { const char *type, *host; } host_filesystems[] = {
    {"proc", "/proc"}, {"sysfs", "/sys"}, {"devpts", "/dev/pts"}, {"devtmpfs", "/dev"},
    {"mqueue", "/dev/mqueue"}, {"cgroup", "/sys/fs/cgroup"}, {"cgroup2", "/sys/fs/cgroup"},
    {"securityfs", "/sys/kernel/security"}, {"debugfs", "/sys/kernel/debug"},
    {"tracefs", "/sys/kernel/tracing"}, {"pstore", "/sys/fs/pstore"}, {"bpf", "/sys/fs/bpf"},
    {"configfs", "/sys/kernel/config"}, {"fusectl", "/sys/fs/fuse/connections"},
    {"hugetlbfs", "/dev/hugepages"},
};

static bool guest_string(const char *s, size_t max)
{
    return s && strnlen(s, max) < max;
}

/* The mount id of a resolved guest path, and its access in the guarded
 * policy ('w' without one). */
static uint32_t mount_access_of(Bridge *b, const char *guest)
{
#ifdef GUARDED
    size_t id;
    if (!g_payload_config.mount_access_observe[0] || g_payload_config.guard < GUARD_PATHS ||
        binding_table_mount_id(&b->table, guest, &id) < 0)
        return 'w';
    if (id <= (size_t)g_payload_config.bind_count) {
        char c = g_payload_config.mount_access_observe[id];
        return c == 'r' || c == 'd' ? (uint32_t)c : 'w';
    }
    size_t slot = id - 1 - (size_t)g_payload_config.bind_count;
    return slot < (size_t)b->mount_count && b->mounts[slot].access ? b->mounts[slot].access : 'd';
#else
    (void)b; (void)guest;
    return 'w';
#endif
}

static uint32_t cap_access(uint32_t access, unsigned long flags)
{
    return (flags & MS_RDONLY_) && access == 'w' ? 'r' : access;
}

/* A directory of its own under the mount scratch (never reused, so a
 * remount cannot show an old tmpfs). */
static long scratch_dir(Bridge *b, char *host, unsigned mode)
{
    const char *base = g_payload_config.mount_scratch;
    if (!base[0])
        return -EPERM;
    static unsigned long serial;
    long pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    for (int attempt = 0; attempt < 64; attempt++) {
        unsigned long n = __atomic_add_fetch(&serial, 1, __ATOMIC_RELAXED);
        char name[48] = "/tmpfs-";
        size_t at = strlen(name);
        char digits[24];
        int count = 0;
        unsigned long v = (unsigned long)pid;
        do { digits[count++] = '0' + v % 10; v /= 10; } while (v);
        while (count) name[at++] = digits[--count];
        name[at++] = '-';
        v = n;
        do { digits[count++] = '0' + v % 10; v /= 10; } while (v);
        while (count) name[at++] = digits[--count];
        name[at] = 0;
        if (strlen(base) + at >= CONFIG_MAX_PATH)
            return -ENAMETOOLONG;
        strcpy(host, base);
        strcat(host, name);
        long rc = raw_syscall(__NR_mkdirat, AT_FDCWD, (long)host, 0700, 0, 0, 0);
        if (rc == -EEXIST)
            continue;
        if (rc < 0)
            return rc;
        raw_syscall(__NR_fchmodat, AT_FDCWD, (long)host, (mode & 07777) | 0700, 0, 0, 0);
        if (owners_enabled()) {
            struct stat st;
            if (!raw_syscall(__NR_newfstatat, AT_FDCWD, (long)host, (long)&st, 0, 0, 0))
                owners_chmod_done(&st, mode, (mode & 07777) | 0700);
        }
        (void)b;
        return 0;
    }
    return -EEXIST;
}

/* "mode=1777,uid=0,size=64m": the options a tmpfs keeps. */
static void tmpfs_options(const char *data, unsigned *mode, long *uid, long *gid)
{
    for (const char *p = data; p && *p;) {
        const char *end = strchr(p, ',');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        long value = 0;
        int base = !strncmp(p, "mode=", 5) ? 8 : 10;
        const char *v = !strncmp(p, "mode=", 5) ? p + 5 : !strncmp(p, "uid=", 4) ? p + 4 :
            !strncmp(p, "gid=", 4) ? p + 4 : NULL;
        if (v) {
            for (; v < p + len && *v >= '0' && *v <= (base == 8 ? '7' : '9'); v++)
                value = value * base + (*v - '0');
            if (p[0] == 'm') *mode = (unsigned)value & 07777;
            else if (p[0] == 'u') *uid = value;
            else *gid = value;
        }
        p = end ? end + 1 : NULL;
    }
}

/* ---- R6 loop devices (container_state.h): /dev/loop-control and
 * /dev/loop0..7 are the payload's own. Opening one gives a memfd named
 * after it ("elf-loop3"), so the ioctls tell the device from the FD's own
 * link, through fork and dup alike; stat shows the block or character
 * device. A loop mount of an erofs image is a read-only merged view whose
 * only lower is a cache of the image (lazy_layer.h). */
#define LOOP_CONTROL (-2)
#define LO_FLAGS_READ_ONLY_ 1u
#define LO_FLAGS_AUTOCLEAR_ 4u
#define LO_FLAGS_SETTABLE_ (4u | 8u | 16u) /* AUTOCLEAR, PARTSCAN, DIRECT_IO */
#define EROFS_MAGIC_ 0xE0F5E1E2u

/* LOOP_CONTROL, a loop number, or -1 for any other guest path. */
int pb_loop_device(const char *guest)
{
    if (strncmp(guest, "/dev/loop", 9)) return -1;
    const char *p = guest + 9;
    if (!strcmp(p, "-control")) return LOOP_CONTROL;
    if (p[0] >= '0' && p[0] < '0' + MOUNT_LOOPS && !p[1]) return p[0] - '0';
    return -1;
}

/* The device a FD of loop_open is, as pb_loop_device; -1 for another FD. */
static int loop_fd(int fd)
{
    char link[32] = "/proc/self/fd/", target[64], digits[12];
    unsigned v = (unsigned)fd;
    size_t at = strlen(link);
    int nd = 0;
    if (fd < 0) return -1;
    do { digits[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (nd) link[at++] = digits[--nd];
    link[at] = 0;
    long n = raw_syscall(__NR_readlinkat, AT_FDCWD, (long)link, (long)target, sizeof(target) - 1, 0, 0);
    if (n < 0) return -1;
    target[n] = 0;
    static const char prefix[] = "/memfd:elf-loop";
    if (strncmp(target, prefix, sizeof(prefix) - 1)) return -1;
    const char *p = target + sizeof(prefix) - 1;
    if (!strncmp(p, "-control", 8) && (p[8] == 0 || p[8] == ' ')) return LOOP_CONTROL;
    if (p[0] >= '0' && p[0] < '0' + MOUNT_LOOPS && (p[1] == 0 || p[1] == ' ')) return p[0] - '0';
    return -1;
}

/* ioctl and stat buffers of the guest: copied directly, as the stat
 * post-processing does (process_vm_* is refused with --isolate). */
static long guest_copy_out(void *to, const void *from, size_t n)
{
    if (!to) return -EFAULT;
    memcpy(to, from, n);
    return 0;
}

static long guest_copy_in(void *to, const void *from, size_t n)
{
    if (!from) return -EFAULT;
    memcpy(to, from, n);
    return 0;
}

/* A path call on a loop device of the guest. */
long pb_loop_path_call(long number, long a[6], int device)
{
    unsigned mode = device == LOOP_CONTROL ? 0020660 : 0060660;
    unsigned major = device == LOOP_CONTROL ? 10 : 7, minor = device == LOOP_CONTROL ? 237 : (unsigned)device;
    switch (number) {
    case __NR_openat: {
        if ((a[2] & O_CREAT) && (a[2] & O_EXCL)) return -EEXIST;
        if (a[2] & O_DIRECTORY) return -ENOTDIR;
        char name[24] = "elf-loop";
        if (device == LOOP_CONTROL) strcat(name, "-control");
        else { name[8] = (char)('0' + device); name[9] = 0; }
        return raw_syscall(__NR_memfd_create, (long)name, (a[2] & O_CLOEXEC) ? 1 /* MFD_CLOEXEC */ : 0,
                           0, 0, 0, 0);
    }
    case __NR_newfstatat: {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_mode = mode;
        st.st_nlink = 1;
        st.st_rdev = (major << 8) | minor;
        st.st_blksize = 4096;
        return guest_copy_out((void *)a[2], &st, sizeof(st));
    }
    case __NR_statx: {
        unsigned char sx[256];
        memset(sx, 0, sizeof(sx));
        uint32_t mask = 0x7ff, blksize = 4096, nlink = 1;  /* STATX_BASIC_STATS */
        uint16_t m = (uint16_t)mode;
        memcpy(sx, &mask, 4);
        memcpy(sx + 4, &blksize, 4);
        memcpy(sx + 16, &nlink, 4);
        memcpy(sx + 28, &m, 2);
        memcpy(sx + 128, &major, 4);
        memcpy(sx + 132, &minor, 4);
        return guest_copy_out((void *)a[4], sx, sizeof(sx));
    }
    case __NR_faccessat: case __NR_faccessat2:
        return 0;
    case __NR_readlinkat:
        return -EINVAL;
    case __NR_mknodat:
        return -EEXIST;
    default:
        return -EPERM;
    }
}

/* Whether a live mount shows loop device n (its source is /dev/loopN). */
static bool loop_mounted(int n)
{
    struct mount_entry *mounts = (struct mount_entry *)proot_scratch_alloc(sizeof(struct mount_entry) * CONFIG_MAX_MOUNTS);
    if ((unsigned long)mounts >= (unsigned long)-4095) return true; /* (keep it bound) */
    int count = mounts_snapshot(mounts, CONFIG_MAX_MOUNTS);
    char name[16] = "/dev/loop";
    name[9] = (char)('0' + n);
    name[10] = 0;
    bool found = false;
    for (int i = 0; i < count && !found; i++)
        found = mounts[i].guest[0] && !strcmp(mounts[i].source, name);
    proot_scratch_free(mounts, sizeof(struct mount_entry) * CONFIG_MAX_MOUNTS);
    return found;
}

/* struct loop_info64: offset 24, sizelimit 32, number 40, flags 52,
 * file name 56 (64 bytes); 232 bytes. */
static void loop_info_out(unsigned char *info, int n, const struct mount_loop *l)
{
    memset(info, 0, 232);
    memcpy(info + 8, &l->ino, 8);
    memcpy(info + 16, &l->dev, 8);
    memcpy(info + 24, &l->offset, 8);
    memcpy(info + 32, &l->sizelimit, 8);
    uint32_t number = (uint32_t)n;
    memcpy(info + 40, &number, 4);
    memcpy(info + 52, &l->flags, 4);
    memcpy(info + 56, l->name, 63);
}

static long loop_set_status(int n, const unsigned char *info)
{
    struct mount_loop l;
    long rc = mounts_loop_get(n, &l);
    if (rc < 0) return rc;
    uint32_t flags;
    memcpy(&l.offset, info + 24, 8);
    memcpy(&l.sizelimit, info + 32, 8);
    memcpy(&flags, info + 52, 4);
    l.flags = (l.flags & ~LO_FLAGS_SETTABLE_) | (flags & LO_FLAGS_SETTABLE_);
    memcpy(l.name, info + 56, 63);
    l.name[63] = 0;
    return mounts_loop_status(n, &l);
}

static long loop_set_fd(int n, int file)
{
    struct mount_loop l;
    memset(&l, 0, sizeof(l));
    struct stat st;
    long rc = raw_syscall(__NR_fstat, file, (long)&st, 0, 0, 0, 0);
    if (rc < 0) return -EBADF;
    if ((st.st_mode & S_IFMT) != S_IFREG) return -EINVAL;
    char link[32] = "/proc/self/fd/", digits[12], host[PATH_MAX];
    unsigned v = (unsigned)file;
    size_t at = strlen(link);
    int nd = 0;
    do { digits[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (nd) link[at++] = digits[--nd];
    link[at] = 0;
    long len = raw_syscall(__NR_readlinkat, AT_FDCWD, (long)link, (long)host, sizeof(host) - 1, 0, 0);
    if (len < 0) return len;
    if (len >= CONFIG_MAX_PATH || host[0] != '/') return -ENAMETOOLONG;
    host[len] = 0;
    strcpy(l.file, host);
    l.dev = st.st_dev;
    l.ino = st.st_ino;
    l.size = (uint64_t)st.st_size;
    long fl = raw_syscall(__NR_fcntl, file, 3 /* F_GETFL */, 0, 0, 0, 0);
    if (fl >= 0 && (fl & O_ACCMODE) == O_RDONLY) l.flags |= LO_FLAGS_READ_ONLY_;
    return mounts_loop_bind(n, &l);
}

int proot_loop_ioctl(long fd, unsigned long cmd, long arg, long *result)
{
    bool loop_cmd = (cmd & 0xff00) == 0x4c00;
    bool block_cmd = cmd == 0x80081272 /* BLKGETSIZE64 */ || cmd == 0x1260 /* BLKGETSIZE */ ||
        cmd == 0x1268 /* BLKSSZGET */ || cmd == 0x125e /* BLKROGET */ || cmd == 0x1261 /* BLKFLSBUF */;
    if (!loop_cmd && !block_cmd) return 0;
    int device = loop_fd((int)fd);
    if (device == -1) return 0;
    long rc = -ENOTTY;
    struct mount_loop l;
    if (device == LOOP_CONTROL) {
        if (cmd == 0x4c82) rc = mounts_loop_free();              /* LOOP_CTL_GET_FREE */
        else if (cmd == 0x4c80) rc = arg >= 0 && arg < MOUNT_LOOPS ? -EEXIST : -ENOSPC; /* ADD */
        else if (cmd == 0x4c81) rc = mounts_loop_get((int)arg, &l) == 0 ? -EBUSY : -EPERM; /* REMOVE */
        *result = rc;
        return 1;
    }
    unsigned char info[232];
    switch (cmd) {
    case 0x4c00: /* LOOP_SET_FD */
        rc = loop_set_fd(device, (int)arg);
        break;
    case 0x4c0a: { /* LOOP_CONFIGURE: fd, block_size, loop_info64, reserved */
        unsigned char config[8 + 232];
        rc = guest_copy_in(config, (void *)arg, sizeof(config));
        if (rc < 0) break;
        uint32_t file;
        memcpy(&file, config, 4);
        rc = loop_set_fd(device, (int)file);
        if (rc == 0) rc = loop_set_status(device, config + 8);
        if (rc < 0 && rc != -EBUSY) mounts_loop_bind(device, NULL);
        break;
    }
    case 0x4c01: /* LOOP_CLR_FD: while mounted, at the umount */
        rc = mounts_loop_get(device, &l);
        if (rc < 0) break;
        if (loop_mounted(device)) {
            l.flags |= LO_FLAGS_AUTOCLEAR_;
            rc = mounts_loop_status(device, &l);
        } else {
            rc = mounts_loop_bind(device, NULL);
        }
        break;
    case 0x4c04: /* LOOP_SET_STATUS64 */
        rc = guest_copy_in(info, (void *)arg, sizeof(info));
        if (rc == 0) rc = loop_set_status(device, info);
        break;
    case 0x4c05: /* LOOP_GET_STATUS64 */
        rc = mounts_loop_get(device, &l);
        if (rc == 0) {
            loop_info_out(info, device, &l);
            rc = guest_copy_out((void *)arg, info, sizeof(info));
        }
        break;
    case 0x4c02: case 0x4c03: /* the old loop_info: unbound tells ENXIO */
        rc = mounts_loop_get(device, &l);
        if (rc == 0) rc = -EINVAL;
        break;
    case 0x4c07: case 0x4c08: case 0x4c09: /* SET_CAPACITY, DIRECT_IO, BLOCK_SIZE */
        rc = mounts_loop_get(device, &l);
        break;
    case 0x80081272: case 0x1260: { /* BLKGETSIZE64, BLKGETSIZE */
        rc = mounts_loop_get(device, &l);
        uint64_t size = rc < 0 ? 0 : l.size > l.offset ? l.size - l.offset : 0;
        if (l.sizelimit && size > l.sizelimit) size = l.sizelimit;
        if (cmd == 0x1260) size >>= 9;
        rc = guest_copy_out((void *)arg, &size, 8);
        break;
    }
    case 0x1268: { /* BLKSSZGET */
        int sector = 512;
        rc = guest_copy_out((void *)arg, &sector, 4);
        break;
    }
    case 0x125e: { /* BLKROGET */
        int ro = mounts_loop_get(device, &l) == 0 && (l.flags & LO_FLAGS_READ_ONLY_);
        rc = guest_copy_out((void *)arg, &ro, 4);
        break;
    }
    case 0x1261: /* BLKFLSBUF */
        rc = 0;
        break;
    }
    *result = rc;
    return 1;
}

/* Whether host is an erofs image the payload can expand (an image of an
 * uncompressed layout is checked as it is expanded). */
static long erofs_image(const char *host)
{
    long fd = raw_syscall(__NR_openat, AT_FDCWD, (long)host, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return fd;
    uint32_t magic = 0;
    long n = raw_syscall(__NR_pread64, fd, (long)&magic, 4, 1024, 0, 0);
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return n == 4 && magic == EROFS_MAGIC_ ? 0 : -EINVAL;
}

/* Filesystems a block device could hold: a loop mount of another type is
 * "wrong fs type" (busybox tries the next one) rather than ENODEV. */
static bool block_filesystem(const char *type)
{
    static const char *const types[] = {"ext2", "ext3", "ext4", "vfat", "msdos", "exfat", "squashfs",
                                        "iso9660", "udf", "xfs", "btrfs", "f2fs", "ntfs", "ntfs3",
                                        "cramfs", "romfs", "minix", "hfsplus", "jfs", "reiserfs"};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
        if (!strcmp(type, types[i])) return true;
    return false;
}

/* mount of a loop device or (erofs, as Linux 6.12 can) of an image file. 1
 * with *result when the source is one; 0: not a loop mount. */
static int loop_mount(Bridge *b, const char *guest, const char *source, const char *type,
                      unsigned long flags, unsigned long per_mount, struct mount_entry *e, long *result)
{
    if (!source || !*source) return 0;
    long ret = pb_resolve(b, AT_FDCWD, source, true);
    if (ret < 0) return 0;
    int device = pb_loop_device(b->guest);
    char image[CONFIG_MAX_PATH], label[64];
    struct mount_loop l;
    if (device >= 0) {
        if (mounts_loop_get(device, &l) < 0) { *result = -ENXIO; return 1; }
        if (l.offset) { *result = -EINVAL; return 1; } /* (an image at offset 0 only) */
        strcpy(image, l.file);
        strcpy(label, "/dev/loop0");
        label[9] = (char)('0' + device);
    } else {
        struct stat st;
        if (device == LOOP_CONTROL || strcmp(type, "erofs") ||
            raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st, 0, 0, 0) < 0 ||
            (st.st_mode & S_IFMT) != S_IFREG)
            return 0;
        if (strlen(b->host) >= CONFIG_MAX_PATH) { *result = -ENAMETOOLONG; return 1; }
        strcpy(image, b->host);
        memset(label, 0, sizeof(label));
        strncpy(label, b->guest, sizeof(label) - 1);
    }
    if (strcmp(type, "erofs")) {
        *result = block_filesystem(type) ? -EINVAL : -ENODEV;
        return 1;
    }
    if ((ret = erofs_image(image)) < 0) { *result = ret; return 1; }
    char cache[1][CONFIG_MAX_PATH];
    memset(e, 0, sizeof(*e)); /* (resolution may use the same scratch) */
    if ((ret = scratch_dir(b, e->host, 0755)) < 0 || (ret = scratch_dir(b, cache[0], 0755)) < 0) {
        *result = ret;
        return 1;
    }
    strcpy(e->guest, guest);
    strcpy(e->fstype, "erofs");
    memcpy(e->source, label, sizeof(e->source));
    e->flags = (uint32_t)(per_mount | MS_RDONLY_);
    e->access = cap_access(mount_access_of(b, guest) == 'd' ? 'd' : 'w', flags | MS_RDONLY_);
    *result = mounts_add_overlay(e, (const char (*)[CONFIG_MAX_PATH])cache, 1, image);
    return 1;
}

/* After the umount of a loop mount: an auto-clearing device it was the
 * last mount of is freed. */
static void loop_unmounted(const char *source)
{
    int device = pb_loop_device(source);
    struct mount_loop l;
    if (device < 0 || mounts_loop_get(device, &l) < 0 || !(l.flags & LO_FLAGS_AUTOCLEAR_) ||
        loop_mounted(device))
        return;
    mounts_loop_bind(device, NULL);
}

/* R6: mount -t overlay -o lowerdir=A[:B...],upperdir=U,workdir=W: a merged
 * view (union_view.h) at the target. Without upperdir it is read-only (the
 * topmost lowerdir stands in as the upper; the guarded build refuses
 * writes). workdir is accepted and not used. */
static long overlay_mount(Bridge *b, const char *guest, const char *source, const char *data,
                          unsigned long flags, unsigned long per_mount, struct mount_entry *e)
{
    char lowers[CONFIG_MAX_LOWERS + 1][CONFIG_MAX_PATH];
    char upper[CONFIG_MAX_PATH] = "";
    char option[PATH_MAX];
    int count = 0;
    const char *p = data ? data : "";
    while (*p) {
        size_t n = 0;
        while (p[n] && p[n] != ',') n++;
        if (n >= sizeof(option)) return -EINVAL;
        memcpy(option, p, n);
        option[n] = 0;
        p += n + (p[n] == ',');
        bool lower = !strncmp(option, "lowerdir=", 9), up = !strncmp(option, "upperdir=", 9);
        if (!lower && !up) continue; /* workdir, index, redirect_dir... */
        char *value = option + 9;
        while (*value) {
            char *end = value;
            while (*end && (!lower || *end != ':')) end++;
            char saved = *end;
            *end = 0;
            if (lower && count > CONFIG_MAX_LOWERS) return -EINVAL;
            /* An upperdir in the root's lower layer is copied up first. */
            b->union_op = up ? UOP_COPY : UOP_READ;
            long ret = pb_resolve(b, AT_FDCWD, value, true);
            b->union_op = UOP_READ;
            if (ret < 0) return ret;
            struct stat st;
            ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st, 0, 0, 0);
            if (ret < 0) return ret;
            if ((st.st_mode & S_IFMT) != S_IFDIR) return -ENOTDIR;
            if (strlen(b->host) >= CONFIG_MAX_PATH) return -ENAMETOOLONG;
            strcpy(up ? upper : lowers[count++], b->host);
            *end = saved;
            value = *end ? end + 1 : end;
            if (up) break;
        }
    }
    if (!count) return -EINVAL;
    memset(e, 0, sizeof(*e));
    int first = 0;
    if (!upper[0]) {
        strcpy(upper, lowers[0]);
        first = 1;
        per_mount |= MS_RDONLY_;
    }
    if (count - first > CONFIG_MAX_LOWERS) return -EINVAL;
    strcpy(e->host, upper);
    strcpy(e->guest, guest);
    strcpy(e->fstype, "overlay");
    strncpy(e->source, source && *source ? source : "overlay", sizeof(e->source) - 1);
    e->flags = (uint32_t)per_mount;
    e->access = cap_access(mount_access_of(b, guest) == 'd' ? 'd' : 'w', flags | per_mount);
    if (count == first) { /* a single lowerdir, read-only: a plain bind does */
        e->kind = MOUNT_BIND;
        return mounts_add(e);
    }
    return mounts_add_overlay(e, (const char (*)[CONFIG_MAX_PATH])lowers[first], count - first, NULL);
}

long pb_mount_call(Bridge *b, long a[6])
{
    const char *source = (const char *)a[0], *target = (const char *)a[1];
    const char *type = (const char *)a[2], *data = (const char *)a[4];
    unsigned long flags = (unsigned long)a[3];
    if ((flags & MS_MGC_MSK_) == MS_MGC_VAL_)
        flags &= ~MS_MGC_MSK_;
    if (!guest_string(target, PATH_MAX) || (type && !guest_string(type, 64)) ||
        (source && !guest_string(source, PATH_MAX)) || (data && !guest_string(data, 4096)))
        return -EFAULT;
    b->optimistic_allowed = false;
    long ret = pb_resolve(b, AT_FDCWD, target, true);
    if (ret < 0)
        return ret;
    struct stat target_st;
    ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&target_st, 0, 0, 0);
    if (ret < 0)
        return ret;
    char *guest = b->first_guest;
    strcpy(guest, b->guest);
    if (strlen(guest) >= CONFIG_MAX_PATH)
        return -ENAMETOOLONG;
    struct mount_entry *e = (struct mount_entry *)b->proc_data;
    _Static_assert(sizeof(struct mount_entry) <= sizeof(((Bridge *)0)->proc_data), "scratch");
    memset(e, 0, sizeof(*e));
    unsigned long per_mount = flags & (MS_RDONLY_ | MS_NOSUID_ | MS_NODEV_ | MS_NOEXEC_);

    if (flags & MS_REMOUNT_) {
        int slot = mounts_find(b->mounts, b->mount_count, guest);
        if (slot < 0) {
            /* The root and the configured binds cannot change. */
            size_t id;
            if (binding_table_mount_id(&b->table, guest, &id) < 0) return -EINVAL;
            const char *at = id ? b->table.entries[id - 1].guest : "/";
            return strcmp(at, guest) ? -EINVAL : -EPERM;
        }
        uint32_t access = b->mounts[slot].access;
        /* Read-only can always be added; taking it away needs the source's
         * own access again (for a bind, the mount it came from). */
        if (per_mount & MS_RDONLY_) access = cap_access(access, MS_RDONLY_);
        else if (access == 'r' && !(b->mounts[slot].flags & MS_RDONLY_)) access = 'r';
        else if (access == 'r') access = b->mounts[slot].kind == MOUNT_BIND ? access : 'w';
        return mounts_set_flags(guest, (uint32_t)per_mount, access);
    }
    if (flags & MS_MOVE_) {
        if (!source) return -EFAULT;
        ret = pb_resolve(b, AT_FDCWD, source, true);
        if (ret < 0) return ret;
        if (!strcmp(guest, "/") || !strcmp(b->guest, "/")) return -EINVAL;
        if (mounts_find(b->mounts, b->mount_count, b->guest) < 0) return -EINVAL;
        if (!strcmp(b->guest, guest)) return 0;
        Comparison c = compare_paths(b->guest, guest);
        if (c == PATH1_IS_PREFIX) return -ELOOP;
        return mounts_move(b->guest, guest);
    }
    if (flags & MS_BIND_) {
        if (!source) return -EFAULT;
        if (!strcmp(guest, "/")) return -EINVAL; /* the root stays the root */
        ret = pb_resolve(b, AT_FDCWD, source, true);
        if (ret < 0) return ret;
        struct stat st;
        ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st, 0, 0, 0);
        if (ret < 0) return ret;
        memset(e, 0, sizeof(*e)); /* resolution may use the same scratch */
        if (((st.st_mode & S_IFMT) == S_IFDIR) != ((target_st.st_mode & S_IFMT) == S_IFDIR))
            return -ENOTDIR;
        /* R6: a bind of the merged view is merged too (named by the upper). */
        if (b->union_on && pb_bridge_alias(b, b->host, b->union_named)) strcpy(b->host, b->union_named);
        if (strlen(b->host) >= CONFIG_MAX_PATH) return -ENAMETOOLONG;
        strcpy(e->host, b->host);
        strcpy(e->guest, guest);
        e->kind = MOUNT_BIND;
        e->flags = (uint32_t)per_mount;
        e->access = cap_access(mount_access_of(b, b->guest), flags);
        /* Shown as the source's filesystem, like the kernel does. */
        int from = -1;
        size_t id;
        if (binding_table_mount_id(&b->table, b->guest, &id) >= 0 && id > (size_t)g_payload_config.bind_count)
            from = (int)(id - 1 - (size_t)g_payload_config.bind_count);
        if (from >= 0 && from < b->mount_count) {
            memcpy(e->source, b->mounts[from].source, sizeof(e->source));
            memcpy(e->fstype, b->mounts[from].fstype, sizeof(e->fstype));
        } else {
            const char *name = mounts_fs_name(b->host);
            strncpy(e->fstype, name, sizeof(e->fstype) - 1);
            strncpy(e->source, strcmp(name, "proc") && strcmp(name, "sysfs") && strcmp(name, "devpts") &&
                    strcmp(name, "tmpfs") ? "/dev/root" : name, sizeof(e->source) - 1);
        }
        char *source_guest = b->first_host; /* the source, canonical */
        strcpy(source_guest, b->guest);
        ret = mounts_add(e);
        if (ret < 0 || !(flags & MS_REC_))
            return ret;
        /* --rbind: the mounts below the source appear below the target. */
        size_t slen = strlen(source_guest), glen = strlen(guest);
        for (size_t i = 0; i < b->table.count; i++) {
            const PathBinding *p = &b->table.entries[i];
            if (p->guest == UNMOUNTED || compare_paths(source_guest, p->guest) != PATH1_IS_PREFIX)
                continue;
            const char *rest = p->guest + (slen == 1 ? 0 : slen);
            if (glen + strlen(rest) >= CONFIG_MAX_PATH || strlen(p->host) >= CONFIG_MAX_PATH)
                return -ENAMETOOLONG;
            struct mount_entry *sub = e;
            strcpy(sub->guest, guest);
            strcat(sub->guest, rest);
            strcpy(sub->host, p->host);
            sub->access = cap_access(mount_access_of(b, p->guest), flags);
            if (i >= (size_t)g_payload_config.bind_count) {
                const struct mount_entry *m = &b->mounts[i - (size_t)g_payload_config.bind_count];
                memcpy(sub->source, m->source, sizeof(sub->source));
                memcpy(sub->fstype, m->fstype, sizeof(sub->fstype));
                sub->flags = m->flags | (uint32_t)per_mount;
            } else {
                const char *name = mounts_fs_name(p->host);
                memset(sub->fstype, 0, sizeof(sub->fstype));
                memset(sub->source, 0, sizeof(sub->source));
                strncpy(sub->fstype, name, sizeof(sub->fstype) - 1);
                strncpy(sub->source, name, sizeof(sub->source) - 1);
            }
            ret = mounts_add(sub);
            if (ret < 0) return ret;
        }
        return 0;
    }
    if (flags & MS_PROPAGATION_)
        return 0; /* --make-private and the like: nothing propagates anyway */
    if (!type) return -EFAULT;
    if (!strcmp(guest, "/")) return -EBUSY;
    if ((target_st.st_mode & S_IFMT) != S_IFDIR) return -ENOTDIR;
    if (!strcmp(type, "overlay"))
        return overlay_mount(b, guest, source, data, flags, per_mount, e);
    long loop_result;
    if (loop_mount(b, guest, source, type, flags, per_mount, e, &loop_result))
        return loop_result;
    const char *host = NULL;
    for (size_t i = 0; i < sizeof(host_filesystems) / sizeof(host_filesystems[0]); i++)
        if (!strcmp(type, host_filesystems[i].type))
            host = host_filesystems[i].host;
    bool tmpfs = !strcmp(type, "tmpfs") || !strcmp(type, "ramfs");
    if (!host && !tmpfs)
        return -ENODEV; /* overlay, block devices, network filesystems, FUSE */
    struct stat st;
    if (host && (raw_syscall(__NR_newfstatat, AT_FDCWD, (long)host, (long)&st, 0, 0, 0) < 0 ||
                 (st.st_mode & S_IFMT) != S_IFDIR))
        host = NULL, tmpfs = true; /* missing on this host: an empty directory */
    e->kind = host ? MOUNT_HOST : MOUNT_TMPFS;
    if (host) {
        strcpy(e->host, host);
    } else {
        unsigned mode = 01777;
        long uid = -1, gid = -1;
        tmpfs_options(data, &mode, &uid, &gid);
        ret = scratch_dir(b, e->host, mode);
        if (ret < 0) return ret;
        if (owners_enabled() && (uid > 0 || gid > 0) &&
            !raw_syscall(__NR_newfstatat, AT_FDCWD, (long)e->host, (long)&st, 0, 0, 0))
            owners_chown(&st, uid, gid);
    }
    strcpy(e->guest, guest);
    strncpy(e->fstype, type, sizeof(e->fstype) - 1);
    strncpy(e->source, source && *source ? source : type, sizeof(e->source) - 1);
    e->flags = (uint32_t)per_mount;
    e->access = cap_access(mount_access_of(b, guest) == 'd' ? 'd' : host ? mount_access_of(b, guest) : 'w',
                           flags);
    return mounts_add(e);
}

long pb_umount_call(Bridge *b, long a[6])
{
    const char *target = (const char *)a[0];
    long flags = (int)a[1];
    if (flags & ~(1 | 2 | 4 | 8)) /* MNT_FORCE, MNT_DETACH, MNT_EXPIRE, UMOUNT_NOFOLLOW */
        return -EINVAL;
    if (!guest_string(target, PATH_MAX))
        return -EFAULT;
    b->optimistic_allowed = false;
    long ret = pb_resolve(b, AT_FDCWD, target, !(flags & 8));
    if (ret < 0)
        return ret;
    if (mounts_find(b->mounts, b->mount_count, b->guest) < 0) {
        size_t id;
        if (binding_table_mount_id(&b->table, b->guest, &id) < 0) return -EINVAL;
        const char *at = id ? b->table.entries[id - 1].guest : "/";
        return strcmp(at, b->guest) ? -EINVAL : -EBUSY;
    }
    int slot = mounts_find(b->mounts, b->mount_count, b->guest);
    char source[sizeof(b->mounts[0].source)] = "";
    if (slot >= 0) memcpy(source, b->mounts[slot].source, sizeof(source));
    source[sizeof(source) - 1] = 0;
    ret = mounts_remove(b->guest, (flags & 2) != 0);
    if (!ret) loop_unmounted(source);
    return ret;
}

/* /proc/filesystems with emulated mounts: the types mount(2) takes here
 * (HongMeng has no such file; mount -o loop without -t reads it). */
long pb_proc_filesystems(Bridge *b, int flags)
{
    if (strcmp(b->guest, "/proc/filesystems")) return -ENOENT;
    long fd = raw_syscall(__NR_memfd_create, (long)"filesystems", (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
    if (fd < 0) return fd;
    char text[1024];
    size_t at = 0;
    static const char *const nodev[] = {"tmpfs", "ramfs", "overlay"};
    for (size_t i = 0; i < sizeof(host_filesystems) / sizeof(host_filesystems[0]) + 3; i++) {
        const char *name = i < 3 ? nodev[i] : host_filesystems[i - 3].type;
        size_t n = strlen(name);
        if (at + 7 + n > sizeof(text)) break;
        memcpy(text + at, "nodev\t", 6);
        memcpy(text + at + 6, name, n);
        text[at + 6 + n] = '\n';
        at += 7 + n;
    }
    memcpy(text + at, "\terofs\n", 7);
    at += 7;
    long rc = raw_syscall(__NR_write, fd, (long)text, (long)at, 0, 0, 0);
    if (rc >= 0) rc = raw_syscall(__NR_lseek, fd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        return rc;
    }
    return fd;
}
