/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Layer images expanded on demand (lazy_layer.h). Built into the payload
 * (plain mode: it expands itself) and into the loader (the broker expands
 * for an isolated guest; the initial loader for its program and cwd). */
#include <asm/stat.h>
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include "lazy_layer.h"

#ifdef LAZY_LOADER
long z_syscall(int n, ...);
static long sys(long n, long a, long b, long c, long d, long e, long f)
{
    return z_syscall((int)n, a, b, c, d, e, f);
}
#else
extern long raw_syscall(long, long, long, long, long, long, long);
static long sys(long n, long a, long b, long c, long d, long e, long f)
{
    return raw_syscall(n, a, b, c, d, e, f);
}
#endif

#define AT_FDCWD_ (-100)
#define AT_SYMLINK_NOFOLLOW_ 0x100
#define AT_REMOVEDIR_ 0x200
#define O_RDONLY_ 0
#define O_WRONLY_ 1
#define O_CREAT_ 0100
#define O_EXCL_ 0200
#define O_DIRECTORY_ 040000 /* AArch64 values */
#define O_NOFOLLOW_ 0100000
#define O_CLOEXEC_ 02000000
#define LOCK_EX_ 2
#define S_IFMT_ 0170000
#define S_IFDIR_ 0040000
#define S_IFREG_ 0100000
#define S_IFLNK_ 0120000
#define S_IFIFO_ 0010000

#define EROFS_MAGIC 0xE0F5E1E2u
#define EROFS_SB_OFFSET 1024
#define LAYOUT_FLAT_PLAIN 0
#define LAYOUT_FLAT_INLINE 2
#define MAX_BLOCK 4096

struct image {
    int fd;
    unsigned blkbits;
    uint64_t blksz, meta, size, build_time;
    uint32_t build_nsec;
    uint64_t root;
};

struct inode {
    uint64_t nid;
    unsigned mode, layout;
    uint64_t size, mtime;
    uint32_t u, mtime_nsec;
    uint64_t inline_off;
};

/* Mapped per operation: the payload may run on a guest's small stack. */
struct work {
    struct image img;
    unsigned char block[MAX_BLOCK];
    char name[256];
    char target[4096];
    unsigned char copy[65536];
};

static struct work *work_get(void)
{
    long mem = sys(__NR_mmap, 0, sizeof(struct work), 3, 0x22, -1, 0);
    return (unsigned long)mem >= (unsigned long)-4095 ? NULL : (struct work *)mem;
}

static void work_put(struct work *w)
{
    if (w->img.fd >= 0) sys(__NR_close, w->img.fd, 0, 0, 0, 0, 0);
    sys(__NR_munmap, (long)w, sizeof(struct work), 0, 0, 0, 0);
}

static uint64_t le(const unsigned char *p, int n)
{
    uint64_t v = 0;
    for (int i = n - 1; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

static size_t length(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static long pread_all(int fd, void *buffer, uint64_t len, uint64_t off)
{
    unsigned char *p = buffer;
    while (len) {
        long n = sys(__NR_pread64, fd, (long)p, (long)len, (long)off, 0, 0);
        if (n < 0) return n;
        if (n == 0) return -EIO;
        p += n;
        len -= (uint64_t)n;
        off += (uint64_t)n;
    }
    return 0;
}

/* ---------------------------------------------------------------- erofs */
static long image_open(struct image *img, const char *path)
{
    img->fd = (int)sys(__NR_openat, AT_FDCWD_, (long)path, O_RDONLY_ | O_CLOEXEC_, 0, 0, 0);
    if (img->fd < 0) return img->fd;
    struct stat st;
    long rc = sys(__NR_fstat, img->fd, (long)&st, 0, 0, 0, 0);
    if (rc < 0) return rc;
    img->size = (uint64_t)st.st_size;
    unsigned char sb[128];
    if (img->size < EROFS_SB_OFFSET + sizeof(sb)) return -EINVAL;
    rc = pread_all(img->fd, sb, sizeof(sb), EROFS_SB_OFFSET);
    if (rc < 0) return rc;
    if (le(sb, 4) != EROFS_MAGIC) return -EINVAL;
    img->blkbits = sb[12];
    if (img->blkbits < 9 || img->blkbits > 12) return -EOPNOTSUPP;
    img->blksz = 1ull << img->blkbits;
    img->root = le(sb + 14, 2);
    img->build_time = le(sb + 24, 8);
    img->build_nsec = (uint32_t)le(sb + 32, 4);
    img->meta = le(sb + 40, 4) << img->blkbits;
    return 0;
}

static long inode_read(struct image *img, uint64_t nid, struct inode *ino)
{
    unsigned char b[64];
    uint64_t off = img->meta + nid * 32;
    if (nid > (img->size >> 5) || off + 32 > img->size) return -EIO;
    long rc = pread_all(img->fd, b, off + 64 <= img->size ? 64 : 32, off);
    if (rc < 0) return rc;
    unsigned format = (unsigned)le(b, 2);
    bool extended = format & 1;
    if (extended && off + 64 > img->size) return -EIO;
    unsigned xattr_count = (unsigned)le(b + 2, 2);
    ino->nid = nid;
    ino->layout = (format >> 1) & 7;
    ino->mode = (unsigned)le(b + 4, 2);
    ino->u = (uint32_t)le(b + 16, 4);
    if (extended) {
        ino->size = le(b + 8, 8);
        ino->mtime = le(b + 32, 8);
        ino->mtime_nsec = (uint32_t)le(b + 40, 4);
    } else {
        ino->size = le(b + 8, 4);
        ino->mtime = img->build_time;
        ino->mtime_nsec = img->build_nsec;
    }
    ino->inline_off = off + (extended ? 64 : 32) + (xattr_count ? 12 + (uint64_t)(xattr_count - 1) * 4 : 0);
    unsigned type = ino->mode & S_IFMT_;
    if ((type == S_IFREG_ || type == S_IFDIR_ || type == S_IFLNK_) && ino->size &&
        ino->layout != LAYOUT_FLAT_PLAIN && ino->layout != LAYOUT_FLAT_INLINE)
        return -EOPNOTSUPP; /* Compressed or chunked data. */
    return 0;
}

/* Bytes [pos, pos + len) of an inode's data. */
static long data_read(struct image *img, const struct inode *ino, uint64_t pos, void *buffer, uint64_t len)
{
    unsigned char *out = buffer;
    if (pos > ino->size || len > ino->size - pos) return -EIO;
    uint64_t blocks_end = ino->layout == LAYOUT_FLAT_INLINE ? (ino->size >> img->blkbits) << img->blkbits
                                                           : ino->size;
    while (len) {
        uint64_t physical, n;
        if (pos < blocks_end) {
            physical = ((uint64_t)ino->u << img->blkbits) + pos;
            n = blocks_end - pos < len ? blocks_end - pos : len;
        } else {
            physical = ino->inline_off + (pos - blocks_end);
            n = len;
        }
        if (physical > img->size || n > img->size - physical) return -EIO;
        long rc = pread_all(img->fd, out, n, physical);
        if (rc < 0) return rc;
        out += n;
        pos += n;
        len -= n;
    }
    return 0;
}

struct dir_iter {
    uint64_t block, blocks;
    unsigned count, index, used;
};

/* The next entry of a directory: 1 with nid, name (in w->block, not
 * terminated) and its length; 0 at the end; -errno. */
static long dir_next(struct work *w, const struct inode *dir, struct dir_iter *it, uint64_t *nid,
                     const char **name, size_t *name_len)
{
    struct image *img = &w->img;
    while (it->index >= it->count) {
        if (it->block >= it->blocks) return 0;
        uint64_t start = it->block << img->blkbits;
        uint64_t used = dir->size - start < img->blksz ? dir->size - start : img->blksz;
        long rc = data_read(img, dir, start, w->block, used);
        if (rc < 0) return rc;
        it->block++;
        if (used < 12) return -EIO;
        unsigned first = (unsigned)le(w->block + 8, 2);
        if (first % 12 || first < 12 || first > used) return -EIO;
        it->count = first / 12;
        it->index = 0;
        it->used = (unsigned)used;
    }
    unsigned i = it->index++;
    const unsigned char *d = w->block + 12 * i;
    unsigned off = (unsigned)le(d + 8, 2);
    unsigned end = i + 1 < it->count ? (unsigned)le(d + 12 + 8, 2) : it->used;
    if (off < it->count * 12 || end > it->used || off >= end) return -EIO;
    if (i + 1 == it->count)
        while (end > off && !w->block[end - 1]) end--;
    if (end == off || end - off > 255) return -EIO;
    *nid = le(d, 8);
    *name = (const char *)w->block + off;
    *name_len = end - off;
    return 1;
}

static void dir_begin(struct work *w, const struct inode *dir, struct dir_iter *it)
{
    it->block = 0;
    it->blocks = (dir->size + w->img.blksz - 1) >> w->img.blkbits;
    it->count = it->index = 0;
}

static bool same_name(const char *a, size_t al, const char *b, size_t bl)
{
    if (al != bl) return false;
    for (size_t i = 0; i < al; i++)
        if (a[i] != b[i]) return false;
    return true;
}

/* The inode at rel ("" or "/a/b") of the image. */
static long image_lookup(struct work *w, const char *rel, struct inode *ino)
{
    long rc = inode_read(&w->img, w->img.root, ino);
    for (const char *p = rel; rc >= 0 && *p;) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != '/') end++;
        if ((ino->mode & S_IFMT_) != S_IFDIR_) return -ENOTDIR;
        struct dir_iter it;
        dir_begin(w, ino, &it);
        uint64_t nid = 0;
        const char *name;
        size_t nl;
        long found = 0;
        while ((rc = dir_next(w, ino, &it, &nid, &name, &nl)) > 0)
            if (same_name(name, nl, p, (size_t)(end - p))) { found = 1; break; }
        if (rc < 0) return rc;
        if (!found) return -ENOENT;
        rc = inode_read(&w->img, nid, ino);
        p = end;
    }
    return rc < 0 ? rc : 0;
}

/* ---------------------------------------------------------------- cache */
/* The directory at rel of the cache, walked without following symlinks;
 * parent: the directory holding rel's final name (left in w->name). */
static long cache_dir(struct work *w, const char *cache, const char *rel, bool parent)
{
    long fd = sys(__NR_openat, AT_FDCWD_, (long)cache, O_RDONLY_ | O_DIRECTORY_ | O_CLOEXEC_, 0, 0, 0);
    const char *p = rel;
    while (fd >= 0) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *end = p;
        while (*end && *end != '/') end++;
        size_t n = (size_t)(end - p);
        if (n >= sizeof(w->name) || (n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.')) {
            sys(__NR_close, fd, 0, 0, 0, 0, 0);
            return -EINVAL;
        }
        for (size_t i = 0; i < n; i++) w->name[i] = p[i];
        w->name[n] = 0;
        const char *rest = end;
        while (*rest == '/') rest++;
        if (parent && !*rest) break;
        long next = sys(__NR_openat, fd, (long)w->name, O_RDONLY_ | O_DIRECTORY_ | O_NOFOLLOW_ | O_CLOEXEC_,
                        0, 0, 0);
        sys(__NR_close, fd, 0, 0, 0, 0, 0);
        fd = next;
        p = end;
    }
    return fd;
}

static bool exists_at(long dir, const char *name)
{
    struct stat st;
    return sys(__NR_newfstatat, dir, (long)name, (long)&st, AT_SYMLINK_NOFOLLOW_, 0, 0) == 0;
}

static void times_of(const struct inode *ino, long t[4], bool placeholder)
{
    t[0] = placeholder ? LAZY_ATIME_SEC : (long)ino->mtime;
    t[1] = placeholder ? LAZY_ATIME_NSEC : (long)ino->mtime_nsec;
    t[2] = (long)ino->mtime;
    t[3] = (long)ino->mtime_nsec;
}

/* One child made under LAZY_TMP, then renamed to name. */
static long make_child(struct work *w, long dir, const char *name, const struct inode *ino)
{
    long t[4], rc;
    unsigned mode = ino->mode & 07777;
    times_of(ino, t, false);
    switch (ino->mode & S_IFMT_) {
    case S_IFDIR_:
        rc = sys(__NR_mkdirat, dir, (long)LAZY_TMP, 0700, 0, 0, 0);
        if (rc < 0) return rc;
        sys(__NR_fchmodat, dir, (long)LAZY_TMP, mode | 0700, 0, 0, 0);
        break;
    case S_IFLNK_:
        if (ino->size == 0 || ino->size >= sizeof(w->target)) return -EIO;
        rc = data_read(&w->img, ino, 0, w->target, ino->size);
        if (rc < 0) return rc;
        w->target[ino->size] = 0;
        if (length(w->target) != ino->size) return -EIO;
        rc = sys(__NR_symlinkat, (long)w->target, dir, (long)LAZY_TMP, 0, 0, 0);
        if (rc < 0) return rc;
        break;
    case S_IFIFO_:
        /* No content to complete, so made at its own name (some storage,
         * HarmonyOS app storage, refuses to rename one); storage that
         * refuses FIFOs skips them. HarmonyOS refuses any later change of
         * a FIFO: the mode is then the image's under the umask. */
        if (sys(__NR_mknodat, dir, (long)name, S_IFIFO_ | (mode & 0777), 0, 0, 0) < 0) return 0;
        sys(__NR_fchmodat, dir, (long)name, mode, 0, 0, 0);
        sys(__NR_utimensat, dir, (long)name, (long)t, AT_SYMLINK_NOFOLLOW_, 0, 0);
        return 0;
    case S_IFREG_: {
        long fd = sys(__NR_openat, dir, (long)LAZY_TMP, O_WRONLY_ | O_CREAT_ | O_EXCL_ | O_CLOEXEC_, 0600, 0, 0);
        if (fd < 0) return fd;
        rc = ino->size ? sys(__NR_ftruncate, fd, (long)ino->size, 0, 0, 0, 0) : 0;
        if (rc >= 0) {
            rc = sys(__NR_fchmod, fd, mode, 0, 0, 0, 0);
            if (rc == -EPERM) rc = sys(__NR_fchmod, fd, mode & ~06000u, 0, 0, 0, 0);
        }
        if (rc >= 0) {
            times_of(ino, t, ino->size != 0);
            rc = sys(__NR_utimensat, fd, 0, (long)t, 0, 0, 0);
        }
        if (rc >= 0 && ino->size) {
            /* The placeholder mark must hold on this file system. */
            struct stat st;
            rc = sys(__NR_fstat, fd, (long)&st, 0, 0, 0, 0);
            if (rc >= 0 && !lazy_placeholder_times((long)st.st_atime, (long)st.st_atime_nsec))
                rc = -EOPNOTSUPP;
        }
        sys(__NR_close, fd, 0, 0, 0, 0, 0);
        if (rc < 0) {
            sys(__NR_unlinkat, dir, (long)LAZY_TMP, 0, 0, 0, 0);
            return rc;
        }
        return sys(__NR_renameat2, dir, (long)LAZY_TMP, dir, (long)name, 0, 0);
    }
    default:
        return 0; /* Devices and sockets are skipped. */
    }
    sys(__NR_utimensat, dir, (long)LAZY_TMP, (long)t, AT_SYMLINK_NOFOLLOW_, 0, 0);
    return sys(__NR_renameat2, dir, (long)LAZY_TMP, dir, (long)name, 0, 0);
}

static long expand_at(struct work *w, const char *image, const char *cache, const char *rel)
{
    long rc = image_open(&w->img, image);
    if (rc < 0) return rc;
    struct inode dir;
    rc = image_lookup(w, rel, &dir);
    if (rc < 0) return rc;
    if ((dir.mode & S_IFMT_) != S_IFDIR_) return -ENOTDIR;
    long fd = cache_dir(w, cache, rel, false);
    if (fd < 0) return fd;
    if (exists_at(fd, LAZY_MARKER)) {
        sys(__NR_close, fd, 0, 0, 0, 0, 0);
        return 0;
    }
    rc = sys(__NR_flock, fd, LOCK_EX_, 0, 0, 0, 0);
    if (rc >= 0 && exists_at(fd, LAZY_MARKER)) {
        sys(__NR_close, fd, 0, 0, 0, 0, 0);
        return 0;
    }
    /* A leftover of an interrupted expansion. */
    if (sys(__NR_unlinkat, fd, (long)LAZY_TMP, 0, 0, 0, 0) < 0)
        sys(__NR_unlinkat, fd, (long)LAZY_TMP, AT_REMOVEDIR_, 0, 0, 0);
    struct dir_iter it;
    dir_begin(w, &dir, &it);
    uint64_t nid;
    const char *name;
    size_t nl;
    while (rc >= 0 && (rc = dir_next(w, &dir, &it, &nid, &name, &nl)) > 0) {
        if ((nl == 1 && name[0] == '.') || (nl == 2 && name[0] == '.' && name[1] == '.')) continue;
        char child[256];
        for (size_t i = 0; i < nl; i++) {
            if (name[i] == '/' || !name[i]) { rc = -EIO; break; }
            child[i] = name[i];
        }
        if (rc < 0) break;
        child[nl] = 0;
        if (lazy_own_name(child) || exists_at(fd, child)) continue;
        /* (make_child does not touch w->block, which holds the listing.) */
        struct inode ino;
        rc = inode_read(&w->img, nid, &ino);
        if (rc >= 0) rc = make_child(w, fd, child, &ino);
    }
    if (rc >= 0) {
        long marker = sys(__NR_openat, fd, (long)LAZY_MARKER, O_WRONLY_ | O_CREAT_ | O_CLOEXEC_, 0600, 0, 0);
        rc = marker < 0 ? marker : 0;
        if (marker >= 0) sys(__NR_close, marker, 0, 0, 0, 0, 0);
        long t[4];
        times_of(&dir, t, false);
        if (rc >= 0 && rel[0]) sys(__NR_utimensat, fd, 0, (long)t, 0, 0, 0);
    }
    sys(__NR_close, fd, 0, 0, 0, 0, 0);
    return rc < 0 ? rc : 0;
}

long lazy_expand(const char *image, const char *cache, const char *rel)
{
    struct work *w = work_get();
    if (!w) return -ENOMEM;
    w->img.fd = -1;
    long rc = expand_at(w, image, cache, rel);
    work_put(w);
    return rc;
}

static long fill_at(struct work *w, const char *image, const char *cache, const char *rel)
{
    long dir = cache_dir(w, cache, rel, true);
    if (dir < 0) return dir;
    long fd = sys(__NR_openat, dir, (long)w->name, O_RDONLY_ | O_NOFOLLOW_ | O_CLOEXEC_, 0, 0, 0);
    struct stat st;
    long rc = fd < 0 ? fd : sys(__NR_fstat, fd, (long)&st, 0, 0, 0, 0);
    if (rc < 0 || (st.st_mode & S_IFMT_) != S_IFREG_ ||
        !lazy_placeholder_times((long)st.st_atime, (long)st.st_atime_nsec))
        goto out;
    rc = sys(__NR_flock, fd, LOCK_EX_, 0, 0, 0, 0);
    if (rc >= 0) rc = sys(__NR_fstat, fd, (long)&st, 0, 0, 0, 0);
    if (rc < 0 || !lazy_placeholder_times((long)st.st_atime, (long)st.st_atime_nsec)) goto out;
    struct inode ino;
    rc = image_open(&w->img, image);
    if (rc >= 0) rc = image_lookup(w, rel, &ino);
    if (rc < 0) goto out;
    if ((ino.mode & S_IFMT_) != S_IFREG_ || ino.size != (uint64_t)st.st_size) { rc = -EIO; goto out; }
    unsigned mode = st.st_mode & 07777;
    if (!(mode & 0200)) sys(__NR_fchmod, fd, mode | 0200, 0, 0, 0, 0);
    long out = sys(__NR_openat, dir, (long)w->name, O_WRONLY_ | O_NOFOLLOW_ | O_CLOEXEC_, 0, 0, 0);
    rc = out < 0 ? out : 0;
    for (uint64_t pos = 0; rc >= 0 && pos < ino.size;) {
        uint64_t n = ino.size - pos < sizeof(w->copy) ? ino.size - pos : sizeof(w->copy);
        rc = data_read(&w->img, &ino, pos, w->copy, n);
        for (uint64_t done = 0; rc >= 0 && done < n;) {
            long k = sys(__NR_pwrite64, out, (long)(w->copy + done), (long)(n - done), (long)(pos + done), 0, 0);
            if (k <= 0) rc = k < 0 ? k : -EIO;
            else done += (uint64_t)k;
        }
        pos += n;
    }
    if (out >= 0) sys(__NR_close, out, 0, 0, 0, 0, 0);
    /* A write clears setuid bits; the mode as the placeholder had it. */
    long chmod_rc = sys(__NR_fchmod, fd, ino.mode & 07777, 0, 0, 0, 0);
    if (chmod_rc == -EPERM) sys(__NR_fchmod, fd, ino.mode & 07777 & ~06000u, 0, 0, 0, 0);
    if (rc >= 0) {
        long t[4];
        times_of(&ino, t, false);
        rc = sys(__NR_utimensat, fd, 0, (long)t, 0, 0, 0);
    }
out:
    if (fd >= 0) sys(__NR_close, fd, 0, 0, 0, 0, 0);
    sys(__NR_close, dir, 0, 0, 0, 0, 0);
    return rc < 0 ? rc : 0;
}

long lazy_fill(const char *image, const char *cache, const char *rel)
{
    struct work *w = work_get();
    if (!w) return -ENOMEM;
    w->img.fd = -1;
    long rc = fill_at(w, image, cache, rel);
    work_put(w);
    return rc;
}

long lazy_ensure(const char *image, const char *cache, const char *rel, bool fill)
{
    char prefix[4096];
    size_t n = length(rel);
    if (n >= sizeof(prefix)) return -ENAMETOOLONG;
    long rc = lazy_expand(image, cache, "");
    if (rc < 0) return rc;
    for (size_t i = 1; i <= n; i++) {
        if (i < n && rel[i] != '/') continue;
        for (size_t k = 0; k < i; k++) prefix[k] = rel[k];
        prefix[i] = 0;
        /* The cache's object of this prefix decides. */
        struct work *w = work_get();
        if (!w) return -ENOMEM;
        w->img.fd = -1;
        long dir = cache_dir(w, cache, prefix, true);
        struct stat st;
        rc = dir < 0 ? dir : sys(__NR_newfstatat, dir, (long)w->name, (long)&st, AT_SYMLINK_NOFOLLOW_, 0, 0);
        if (dir >= 0) sys(__NR_close, dir, 0, 0, 0, 0, 0);
        work_put(w);
        if (rc < 0) return 0; /* Not in the image (or not a directory on the way). */
        if ((st.st_mode & S_IFMT_) == S_IFDIR_) {
            rc = lazy_expand(image, cache, prefix);
            if (rc < 0) return rc;
        } else if (i == n && fill && (st.st_mode & S_IFMT_) == S_IFREG_) {
            return lazy_fill(image, cache, prefix);
        } else {
            return 0;
        }
    }
    return 0;
}
