/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Merged view of an upper directory over lower directories (union_view.h,
 * docs/OCI.md R6). Every host call goes through host_syscall: with
 * --isolate the broker executes it within its trees (the lowers are
 * read-only trees there). */
#include <asm/stat.h>
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "container_state.h"
#include "host_syscall.h"
#include "broker_proto.h"
#include "lazy_layer.h"
#include "union_view.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#define AT_FDCWD_ (-100)
#define AT_SYMLINK_NOFOLLOW_ 0x100
#define AT_REMOVEDIR_ 0x200
#define O_RDONLY_ 0
#define O_WRONLY_ 1
#define O_CREAT_ 0100
#define O_EXCL_ 0200
#define O_NOFOLLOW_ 0100000 /* AArch64 values */
#define O_DIRECTORY_ 040000
#define O_CLOEXEC_ 02000000
#define F_DUPFD_CLOEXEC_ 1030
#define S_IFMT_ 0170000
#define S_IFDIR_ 0040000
#define S_IFREG_ 0100000
#define S_IFLNK_ 0120000
#define S_IFIFO_ 0010000
#define RENAME_NOREPLACE_ 1u
#define RENAME_EXCHANGE_ 2u
#define OPAQUE "/.wh..wh..opq"
#define COPY_PREFIX ".wh..elf-copy."

static long hs(long n, long a, long b, long c, long d, long e, long f)
{
    return host_syscall(n, a, b, c, d, e, f);
}

static long lstat_at(const char *path, struct stat *st)
{
    return hs(__NR_newfstatat, AT_FDCWD_, (long)path, (long)st, AT_SYMLINK_NOFOLLOW_, 0, 0);
}

static bool exists(const char *path)
{
    struct stat st;
    return lstat_at(path, &st) == 0;
}

/* out = a + b[0..n) (+ c); -ENAMETOOLONG if it does not fit. */
static int join(char out[PATH_MAX], const char *a, size_t al, const char *b, size_t n, const char *c)
{
    size_t cl = c ? strlen(c) : 0;
    if (al + n + cl >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(out, a, al);
    memcpy(out + al, b, n);
    if (cl) memcpy(out + al + n, c, cl);
    out[al + n + cl] = 0;
    return 0;
}

/* Buffers of one changing operation, mapped for it: the payload may run on
 * a guest's small stack. */
struct scratch {
    char from[PATH_MAX], to[PATH_MAX], tmp[PATH_MAX], target[PATH_MAX];
    char prefix[PATH_MAX], path[PATH_MAX];
    char a[PATH_MAX], b[PATH_MAX], w[PATH_MAX];
    char list[PATH_MAX], child[PATH_MAX];
    unsigned char dents[32768];
    char copy[8192];
    /* union_getdents: the views. */
    struct mount_entry mounts[CONFIG_MAX_MOUNTS];
    char lowers[MOUNT_OVERLAYS * CONFIG_MAX_LOWERS][CONFIG_MAX_PATH];
    struct union_view views[1 + MOUNT_OVERLAYS];
};

static struct scratch *scratch_get(void)
{
    long mem = raw_syscall(__NR_mmap, 0, sizeof(struct scratch), 3, 0x22, -1, 0);
    return (unsigned long)mem >= (unsigned long)-4095 ? NULL : (struct scratch *)mem;
}

static void scratch_put(struct scratch *s)
{
    raw_syscall(__NR_munmap, (long)s, sizeof(struct scratch), 0, 0, 0, 0);
}

static void set_lengths(struct union_view *u)
{
    for (int i = 0; i < u->count; i++) {
        size_t n = strlen(u->layer[i]);
        while (n > 1 && u->layer[i][n - 1] == '/') n--;
        u->length[i] = n == 1 ? 0 : n;
    }
}

bool union_root(struct union_view *u)
{
    const payload_config_t *cfg = &g_payload_config;
    if (cfg->lower_count <= 0 || !cfg->root[0]) return false;
    u->layer[0] = cfg->root;
    u->image[0] = NULL;
    u->count = 1;
    for (int i = 0; i < cfg->lower_count && i < CONFIG_MAX_LOWERS; i++) {
        u->image[u->count] = cfg->lower_image[i][0] ? cfg->lower_image[i] : NULL;
        u->layer[u->count++] = cfg->lower[i];
    }
    set_lengths(u); /* "/" joins as "" + "/rel" */
    return true;
}

bool union_enabled(void)
{
    return g_payload_config.lower_count > 0 || (mounts_enabled() && mounts_overlays());
}

int union_views(struct union_view *views, int max, char (*storage)[CONFIG_MAX_PATH],
                const struct mount_entry *mounts, int mount_count)
{
    int n = 0, used = 0;
    if (n < max && union_root(&views[n])) n++;
    for (int i = 0; i < mount_count && n < max && used < MOUNT_OVERLAYS; i++) {
        if (!mounts[i].guest[0] || mounts[i].kind != MOUNT_OVERLAY) continue;
        char (*lowers)[CONFIG_MAX_PATH] = storage + used * CONFIG_MAX_LOWERS;
        int count = mounts_overlay_lowers(mounts[i].id, lowers, CONFIG_MAX_LOWERS);
        if (count <= 0) continue;
        used++;
        struct union_view *u = &views[n++];
        u->count = 1 + count;
        u->layer[0] = mounts[i].host;
        u->image[0] = NULL;
        for (int k = 0; k < count; k++) { u->layer[1 + k] = lowers[k]; u->image[1 + k] = NULL; }
        set_lengths(u);
    }
    return n;
}

int union_find(const struct union_view *views, int count, const char *host, int *layer, const char **rel)
{
    int best = -1;
    size_t best_length = 0;
    for (int v = 0; v < count; v++) {
        const char *r;
        int l = union_layer_of(&views[v], host, &r);
        if (l < 0 || (best >= 0 && views[v].length[l] <= best_length)) continue;
        best = v;
        best_length = views[v].length[l];
        if (layer) *layer = l;
        if (rel) *rel = r;
    }
    return best;
}

int union_layer_of(const struct union_view *u, const char *host, const char **rel)
{
    for (int i = 0; i < u->count; i++) {
        size_t n = u->length[i];
        if (!strncmp(host, u->layer[i], n) && (host[n] == 0 || host[n] == '/')) {
            if (rel) *rel = host + n;
            return i;
        }
    }
    return -1;
}

int union_alias(const struct union_view *u, const char *host, char out[PATH_MAX])
{
    const char *rel;
    int i = union_layer_of(u, host, &rel);
    if (i <= 0) return 0;
    return join(out, u->layer[0], u->length[0], rel, strlen(rel), NULL) < 0 ? 0 : 1;
}

/* ---------------------------------------------------------------- images */
/* Directories of layer images known expanded (by st_dev and st_ino): the
 * marker is looked up once per process. A lost race only repeats a check. */
#define LAZY_SEEN 1024
static uint64_t lazy_seen[LAZY_SEEN];
static uint32_t lazy_roots; /* root view layers whose top is expanded */

static uint64_t lazy_key(const struct stat *st)
{
    uint64_t h = (uint64_t)st->st_ino * 0x9E3779B97F4A7C15ull ^ (uint64_t)st->st_dev * 0xC2B2AE3D27D4EB4Full;
    return h | 1;
}

/* Expansion or fill (op 1) of host, a path of layer i: by the broker with
 * --isolate (the guest cannot write the cache there). */
static long lazy_call(const struct union_view *u, int i, const char *host, int op)
{
    if (g_payload_config.isolate) return hs(BROKER_LAZY_PATH, (long)host, op, 0, 0, 0, 0);
    const char *rel = host + u->length[i];
    return op ? lazy_fill(u->image[i], u->layer[i], rel) : lazy_expand(u->image[i], u->layer[i], rel);
}

/* The directory at host (layer i, an image; st its lstat) expanded. */
static long lazy_dir(const struct union_view *u, int i, const char *host, const struct stat *st)
{
    uint64_t key = lazy_key(st);
    uint64_t *slot = &lazy_seen[(key >> 7) % LAZY_SEEN];
    if (__atomic_load_n(slot, __ATOMIC_RELAXED) == key) return 0;
    char marker[PATH_MAX];
    if (join(marker, host, strlen(host), "/", 1, LAZY_MARKER) < 0) return -ENAMETOOLONG;
    long rc = exists(marker) ? 0 : lazy_call(u, i, host, 0);
    if (rc == 0) __atomic_store_n(slot, key, __ATOMIC_RELAXED);
    return rc;
}

/* Every image layer's top expanded (once per process). */
static long lazy_tops(const struct union_view *u)
{
    for (int i = 1; i < u->count; i++) {
        if (!u->image[i] || (__atomic_load_n(&lazy_roots, __ATOMIC_RELAXED) & (1u << i))) continue;
        struct stat st;
        long rc = lstat_at(u->layer[i], &st);
        if (rc == 0) rc = lazy_dir(u, i, u->layer[i], &st);
        if (rc < 0) return rc;
        __atomic_or_fetch(&lazy_roots, 1u << i, __ATOMIC_RELAXED);
    }
    return 0;
}

long union_lazy_fill(const struct union_view *u, const char *host)
{
    if (!u) return 0;
    int i = union_layer_of(u, host, NULL);
    if (i <= 0 || !u->image[i]) return 0;
    struct stat st;
    if (lstat_at(host, &st) < 0 || (st.st_mode & S_IFMT_) != S_IFREG_ ||
        !lazy_placeholder_times((long)st.st_atime, (long)st.st_atime_nsec))
        return 0;
    return lazy_call(u, i, host, 1);
}

static bool any_image(void)
{
    static int images = -1;
    if (images < 0) {
        int any = 0;
        for (int i = 0; i < CONFIG_MAX_LOWERS; i++)
            if (g_payload_config.lower_image[i][0]) any = 1;
        images = any;
    }
    return images;
}

extern long raw_syscall(long, long, long, long, long, long, long);

static long fd_host(int fd, char *host);

long union_lazy_fd(int fd)
{
    if (!any_image()) return 0;
    struct stat st;
    if (raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0) < 0 || (st.st_mode & S_IFMT_) != S_IFREG_ ||
        !lazy_placeholder_times((long)st.st_atime, (long)st.st_atime_nsec))
        return 0;
    char host[PATH_MAX];
    long rc = fd_host(fd, host);
    if (rc < 0) return rc;
    struct union_view u;
    return union_root(&u) ? union_lazy_fill(&u, host) : 0;
}

void union_lazy_stat(long number, const long *a)
{
    if (!any_image()) return;
    if (number == __NR_fstat || number == __NR_newfstatat) {
        struct stat *st = (struct stat *)(number == __NR_fstat ? a[1] : a[2]);
        if (!st || (st->st_mode & S_IFMT_) != S_IFREG_ ||
            !lazy_placeholder_times((long)st->st_atime, (long)st->st_atime_nsec))
            return;
        st->st_atime = st->st_mtime;
        st->st_atime_nsec = st->st_mtime_nsec;
        st->st_blocks = (long)(((uint64_t)st->st_size + 4095) / 4096 * 8);
    } else if (number == __NR_statx && a[4]) {
        /* struct statx: mode at 28, size 40, blocks 48, atime 64, mtime 112
         * (a timestamp: 64-bit seconds, 32-bit nanoseconds). */
        unsigned char *b = (unsigned char *)a[4];
        uint32_t mask, nsec;
        uint16_t mode;
        int64_t sec;
        uint64_t size, blocks;
        memcpy(&mask, b, 4);
        memcpy(&mode, b + 28, 2);
        memcpy(&sec, b + 64, 8);
        memcpy(&nsec, b + 72, 4);
        if (!(mask & 0x20 /* STATX_ATIME */) || (mode & S_IFMT_) != S_IFREG_ ||
            !lazy_placeholder_times((long)sec, (long)nsec))
            return;
        if (mask & 0x40 /* STATX_MTIME */) {
            memcpy(b + 64, b + 112, 8);
            memcpy(b + 72, b + 120, 4);
        }
        if (mask & 0x400 /* STATX_BLOCKS */) {
            memcpy(&size, b + 40, 8);
            blocks = (size + 4095) / 4096 * 8;
            memcpy(b + 48, &blocks, 8);
        }
    }
}

/* The walk of rel ("" for the top, else "/a/b"). below: also find out
 * whether a layer other than the upper has the final name. */
static int walk(const struct union_view *u, const char *rel, struct union_hit *hit,
                struct union_memo *memo, bool need_below)
{
    char path[PATH_MAX];
    uint32_t all = (1u << u->count) - 1, mask = all;
    size_t pos = 0, len = strlen(rel);
    while (len && rel[len - 1] == '/') len--;
    if (memo && memo->view != u) memo->valid = false;
    if (memo && memo->valid && memo->length <= len && !strncmp(rel, memo->rel, memo->length) &&
        (rel[memo->length] == '/' || memo->length == len)) {
        mask = memo->mask;
        pos = memo->length;
    }
    hit->layer = -1;
    hit->dir = false;
    hit->below = false;
    hit->whiteout = false;
    hit->dirs = 0;
    long lazy = lazy_tops(u);
    if (lazy < 0) return (int)lazy;
    if (!len) {
        /* The top: every layer's root merges (an opaque upper root hides all). */
        hit->layer = 0;
        hit->dir = true;
        hit->below = u->count > 1;
        hit->dirs = all;
        if (join(path, u->layer[0], u->length[0], OPAQUE, sizeof(OPAQUE) - 1, NULL) == 0 && exists(path))
            hit->dirs = 1;
        return 0;
    }
    if (pos == len) {
        hit->layer = __builtin_ctz(mask);
        hit->dir = true;
        hit->dirs = mask;
        hit->below = (mask & ~1u) != 0;
        return 0;
    }
    while (pos < len) {
        size_t start = pos + 1, next = start;
        while (next < len && rel[next] != '/') next++;
        bool last = next == len;
        if (union_hidden_name(rel + start) && next - start >= 4) {
            hit->layer = -1;
            return 0; /* Never a name of the view. */
        }
        int first = -1;
        bool first_dir = false, stop = false, below = false, whiteout = false;
        uint32_t next_mask = 0;
        for (int i = 0; i < u->count; i++) {
            if (!(mask & (1u << i))) continue;
            int rc = join(path, u->layer[i], u->length[i], rel, next, NULL);
            if (rc < 0) return rc;
            struct stat st;
            if (lstat_at(path, &st) == 0) {
                bool is_dir = (st.st_mode & S_IFMT_) == S_IFDIR_;
                if (is_dir && u->image[i]) {
                    long lr = lazy_dir(u, i, path, &st);
                    if (lr < 0) return (int)lr;
                }
                if (first < 0) { first = i; first_dir = is_dir; }
                if (i > 0) below = true;
                if (!stop) {
                    if (first_dir && is_dir) {
                        next_mask |= 1u << i;
                        /* Opaque: the layers below do not merge in. */
                        if ((mask >> (i + 1)) &&
                            join(path, u->layer[i], u->length[i], rel, next, OPAQUE) == 0 && exists(path))
                            stop = true;
                    } else {
                        stop = true;
                    }
                }
                if (stop && (!last || !need_below || below)) break;
            } else {
                /* A whiteout of this name hides the layers below:
                 * <layer><parent>/.wh.<name>. */
                rc = join(path, u->layer[i], u->length[i], rel, start, ".wh.");
                size_t at = rc < 0 ? 0 : strlen(path);
                if (rc < 0 || at + (next - start) >= PATH_MAX) return -ENAMETOOLONG;
                memcpy(path + at, rel + start, next - start);
                path[at + next - start] = 0;
                if (exists(path)) {
                    if (i == 0 && first < 0) whiteout = true;
                    break;
                }
            }
        }
        if (last) {
            hit->layer = first;
            hit->dir = first >= 0 && first_dir;
            hit->below = below;
            hit->whiteout = whiteout;
            hit->dirs = hit->dir ? next_mask : 0;
            if (memo && hit->dir && next < PATH_MAX) {
                memcpy(memo->rel, rel, next);
                memo->rel[next] = 0;
                memo->length = next;
                memo->mask = next_mask;
                memo->view = u;
                memo->valid = true;
            }
            return 0;
        }
        if (first < 0 || !first_dir) {
            /* Missing (ENOENT) or a non-directory on the way (ENOTDIR):
             * the kernel tells which, from that layer. */
            hit->layer = -1;
            hit->dirs = first < 0 ? 0 : 1u << first;
            return 0;
        }
        mask = next_mask;
        pos = next;
        if (memo && next < PATH_MAX) {
            memcpy(memo->rel, rel, next);
            memo->rel[next] = 0;
            memo->length = next;
            memo->mask = mask;
            memo->view = u;
            memo->valid = true;
        }
    }
    return 0;
}

int union_map(const struct union_view *u, char host[PATH_MAX], struct union_hit *hit,
              struct union_memo *memo)
{
    size_t ul = u->length[0];
    if (strncmp(host, u->layer[0], ul) || (host[ul] && host[ul] != '/')) return 0;
    struct union_hit local;
    if (!hit) hit = &local;
    int rc = walk(u, host + ul, hit, memo, false);
    if (rc < 0) return rc;
    /* A non-directory on the way: that layer answers ENOTDIR. */
    int layer = hit->layer >= 0 ? hit->layer : hit->dirs ? __builtin_ctz(hit->dirs) : 0;
    if (layer > 0) {
        size_t rl = strlen(host + ul), ll = u->length[layer];
        if (ll + rl >= PATH_MAX) return -ENAMETOOLONG;
        memmove(host + ll, host + ul, rl + 1);
        memcpy(host, u->layer[layer], ll);
    }
    return 0;
}

/* ---------------------------------------------------------------- copy-up */
static void parent_of(const char *rel, size_t *slash)
{
    size_t n = strlen(rel);
    while (n && rel[n - 1] == '/') n--;
    while (n && rel[n - 1] != '/') n--;
    *slash = n ? n - 1 : 0; /* rel[0..slash) is the parent ("" for the top) */
}

static long copy_data(long in, long out, char *buffer, size_t size)
{
    for (;;) {
        long n = raw_syscall(__NR_copy_file_range, in, 0, out, 0, 1L << 30, 0);
        if (n == 0) return 0;
        if (n > 0) continue;
        if (n != -EXDEV && n != -ENOSYS && n != -EINVAL && n != -EOPNOTSUPP && n != -EPERM && n != -EACCES)
            return n;
        break;
    }
    for (;;) {
        long n = raw_syscall(__NR_sendfile, out, in, 0, 1L << 30, 0, 0);
        if (n == 0) return 0;
        if (n > 0) continue;
        /* The isolation filter may refuse it: plain reads and writes. */
        if (n != -EINVAL && n != -ENOSYS && n != -EPERM && n != -EACCES) return n;
        break;
    }
    for (;;) {
        long n = raw_syscall(__NR_read, in, (long)buffer, (long)size, 0, 0, 0);
        if (n <= 0) return n;
        for (long done = 0; done < n;) {
            long w = raw_syscall(__NR_write, out, (long)buffer + done, n - done, 0, 0, 0);
            if (w <= 0) return w < 0 ? w : -EIO;
            done += w;
        }
    }
}

static void set_times(const char *path, const struct stat *st)
{
    struct { long sec, nsec; } times[2] = {{(long)st->st_atime, (long)st->st_atime_nsec},
                                           {(long)st->st_mtime, (long)st->st_mtime_nsec}};
    hs(__NR_utimensat, AT_FDCWD_, (long)path, (long)times, AT_SYMLINK_NOFOLLOW_, 0, 0);
}

static void carry_owner(const struct stat *from, const char *to)
{
    struct stat st;
    if (owners_enabled() && lstat_at(to, &st) == 0)
        owners_copied(from, &st);
}

/* One object of layer src at rel to the upper (its parent exists there). */
static long copy_one(struct scratch *s, const struct union_view *u, int src, const char *rel, bool data)
{
    char *from = s->from, *to = s->to;
    size_t len = strlen(rel);
    if (join(from, u->layer[src], u->length[src], rel, len, NULL) < 0 ||
        join(to, u->layer[0], u->length[0], rel, len, NULL) < 0)
        return -ENAMETOOLONG;
    struct stat st;
    long rc = data ? union_lazy_fill(u, from) : 0;
    if (rc < 0) return rc;
    rc = lstat_at(from, &st);
    if (rc < 0) return rc;
    if (lazy_placeholder_times((long)st.st_atime, (long)st.st_atime_nsec)) {
        st.st_atime = st.st_mtime; /* (truncated: the mark is not copied) */
        st.st_atime_nsec = st.st_mtime_nsec;
    }
    unsigned mode = st.st_mode & 07777;
    switch (st.st_mode & S_IFMT_) {
    case S_IFDIR_:
        rc = hs(__NR_mkdirat, AT_FDCWD_, (long)to, mode | 0700, 0, 0, 0);
        if (rc == -EEXIST) return 0;
        if (rc < 0) return rc;
        /* mkdir applies the umask: the copy keeps the lower's mode. */
        hs(__NR_fchmodat, AT_FDCWD_, (long)to, mode | 0700, 0, 0, 0);
        set_times(to, &st);
        carry_owner(&st, to);
        return 0;
    case S_IFLNK_: {
        char *target = s->target;
        long n = hs(__NR_readlinkat, AT_FDCWD_, (long)from, (long)target, PATH_MAX - 1, 0, 0);
        if (n < 0) return n;
        target[n] = 0;
        rc = hs(__NR_symlinkat, (long)target, AT_FDCWD_, (long)to, 0, 0, 0);
        if (rc == -EEXIST) return 0;
        if (rc == 0) carry_owner(&st, to);
        return rc;
    }
    case S_IFIFO_:
        rc = hs(__NR_mknodat, AT_FDCWD_, (long)to, S_IFIFO_ | mode, 0, 0, 0);
        if (rc == -EEXIST) return 0;
        if (rc == 0) carry_owner(&st, to);
        return rc;
    case S_IFREG_:
        break;
    default:
        return -EPERM; /* Devices and sockets do not copy (unpack skips them). */
    }
    /* A regular file: a hidden temporary name, renamed into place. */
    size_t slash;
    parent_of(rel, &slash);
    char *tmp = s->tmp, name[64] = COPY_PREFIX;
    long tid = raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    size_t at = strlen(name);
    char digits[24];
    int nd = 0;
    unsigned long v = (unsigned long)tid;
    do { digits[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (nd) name[at++] = digits[--nd];
    name[at] = 0;
    if (join(tmp, u->layer[0], u->length[0], rel, slash, "/") < 0 ||
        strlen(tmp) + at >= PATH_MAX)
        return -ENAMETOOLONG;
    strcat(tmp, name);
    hs(__NR_unlinkat, AT_FDCWD_, (long)tmp, 0, 0, 0, 0);
    long out = hs(__NR_openat, AT_FDCWD_, (long)tmp, O_WRONLY_ | O_CREAT_ | O_EXCL_ | O_CLOEXEC_, 0600, 0, 0);
    if (out < 0) return out;
    rc = 0;
    if (data && st.st_size) {
        long in = hs(__NR_openat, AT_FDCWD_, (long)from, O_RDONLY_ | O_NOFOLLOW_ | O_CLOEXEC_, 0, 0, 0);
        rc = in < 0 ? in : copy_data(in, out, s->copy, sizeof(s->copy));
        if (in >= 0) raw_syscall(__NR_close, in, 0, 0, 0, 0, 0);
    }
    if (!rc) {
        unsigned host = mode | 0600;
        /* Through the broker with --isolate. */
        rc = hs(__NR_fchmod, out, host, 0, 0, 0, 0);
        if (rc == -EPERM) rc = hs(__NR_fchmod, out, host & ~06000u, 0, 0, 0, 0);
    }
    raw_syscall(__NR_close, out, 0, 0, 0, 0, 0);
    if (!rc) {
        set_times(tmp, &st);
        rc = hs(__NR_renameat2, AT_FDCWD_, (long)tmp, AT_FDCWD_, (long)to, RENAME_NOREPLACE_, 0);
        if (rc == -EEXIST) rc = 0; /* Another process copied it first. */
        else if (rc == -EINVAL || rc == -ENOSYS)
            rc = exists(to) ? 0 : hs(__NR_renameat, AT_FDCWD_, (long)tmp, AT_FDCWD_, (long)to, 0, 0);
        else if (!rc) carry_owner(&st, to);
    }
    hs(__NR_unlinkat, AT_FDCWD_, (long)tmp, 0, 0, 0, 0);
    return rc;
}

/* The parent directories of rel, down from the top, in the upper. */
static long copy_parents(struct scratch *s, const struct union_view *u, const char *rel)
{
    size_t slash;
    parent_of(rel, &slash);
    char *prefix = s->prefix, *path = s->path;
    for (size_t pos = 0; pos < slash;) {
        size_t next = pos + 1;
        while (next < slash && rel[next] != '/') next++;
        if (join(path, u->layer[0], u->length[0], rel, next, NULL) < 0) return -ENAMETOOLONG;
        struct stat st;
        if (lstat_at(path, &st) == 0) {
            if ((st.st_mode & S_IFMT_) != S_IFDIR_) return -ENOTDIR;
        } else {
            memcpy(prefix, rel, next);
            prefix[next] = 0;
            struct union_hit hit;
            long rc = walk(u, prefix, &hit, NULL, false);
            if (rc < 0) return rc;
            if (hit.layer < 0) return hit.dirs ? -ENOTDIR : -ENOENT;
            if (!hit.dir) return -ENOTDIR;
            rc = copy_one(s, u, hit.layer, prefix, false);
            if (rc < 0) return rc;
        }
        pos = next;
    }
    return 0;
}

long union_copy_up(const struct union_view *u, const char *rel, bool data)
{
    struct union_hit hit;
    long rc = walk(u, rel, &hit, NULL, false);
    if (rc < 0) return rc;
    if (hit.layer <= 0) return hit.layer < 0 ? -ENOENT : 0;
    struct scratch *s = scratch_get();
    if (!s) return -ENOMEM;
    rc = copy_parents(s, u, rel);
    if (!rc) rc = copy_one(s, u, hit.layer, rel, data);
    scratch_put(s);
    return rc;
}

/* The upper's whiteout path of rel. */
static int whiteout_path(const struct union_view *u, const char *rel, char out[PATH_MAX])
{
    size_t slash;
    parent_of(rel, &slash);
    size_t len = strlen(rel);
    while (len && rel[len - 1] == '/') len--;
    if (join(out, u->layer[0], u->length[0], rel, slash, "/.wh.") < 0) return -ENAMETOOLONG;
    size_t at = strlen(out), n = len - slash - 1;
    if (at + n >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(out + at, rel + slash + 1, n);
    out[at + n] = 0;
    return 0;
}

static long make_whiteout(struct scratch *s, const struct union_view *u, const char *rel)
{
    char *path = s->w;
    long rc = whiteout_path(u, rel, path);
    if (rc < 0) return rc;
    long fd = hs(__NR_openat, AT_FDCWD_, (long)path, O_WRONLY_ | O_CREAT_ | O_CLOEXEC_, 0600, 0, 0);
    if (fd < 0) return fd;
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return 0;
}

static const char *final_name(const char *rel)
{
    size_t slash;
    parent_of(rel, &slash);
    return rel + slash + 1;
}

long union_prepare_create(const struct union_view *u, const char *rel, bool *opaque)
{
    *opaque = false;
    if (!rel[0]) return -EEXIST;
    if (union_hidden_name(final_name(rel)) && strlen(final_name(rel)) >= 4) return -EPERM;
    struct union_hit hit;
    long rc = walk(u, rel, &hit, NULL, false);
    if (rc < 0) return rc;
    if (hit.layer >= 0) return -EEXIST;
    if (hit.dirs) return -ENOTDIR; /* A non-directory on the way. */
    struct scratch *s = scratch_get();
    if (!s) return -ENOMEM;
    rc = copy_parents(s, u, rel);
    if (!rc && hit.whiteout) {
        rc = whiteout_path(u, rel, s->w);
        if (!rc) rc = hs(__NR_unlinkat, AT_FDCWD_, (long)s->w, 0, 0, 0, 0);
        if (rc == -ENOENT) rc = 0;
        *opaque = true;
    }
    scratch_put(s);
    return rc;
}

long union_make_opaque(const struct union_view *u, const char *rel)
{
    char path[PATH_MAX];
    if (join(path, u->layer[0], u->length[0], rel, strlen(rel), OPAQUE) < 0) return -ENAMETOOLONG;
    /* (One buffer: the callers hold no others.) */
    long fd = hs(__NR_openat, AT_FDCWD_, (long)path, O_WRONLY_ | O_CREAT_ | O_CLOEXEC_, 0600, 0, 0);
    if (fd < 0) return fd;
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return 0;
}

/* Kernel getdents64 record. */
struct dirent64_ {
    uint64_t ino;
    int64_t off;
    unsigned short reclen;
    unsigned char type;
    char name[];
};

/* Whether the merged directory rel (layers in dirs) shows any name. */
static long merged_empty(struct scratch *s, const struct union_view *u, const char *rel, uint32_t dirs)
{
    char *path = s->list, *child = s->child;
    unsigned char *buffer = s->dents;
    size_t len = strlen(rel);
    for (int i = 0; i < u->count; i++) {
        if (!(dirs & (1u << i))) continue;
        if (join(path, u->layer[i], u->length[i], rel, len, NULL) < 0) return -ENAMETOOLONG;
        long fd = hs(__NR_openat, AT_FDCWD_, (long)path, O_RDONLY_ | O_DIRECTORY_ | O_CLOEXEC_, 0, 0, 0);
        if (fd < 0) return fd;
        long found = 0, n;
        while (!found && (n = raw_syscall(__NR_getdents64, fd, (long)buffer, sizeof(s->dents), 0, 0, 0)) > 0) {
            for (long at = 0; at < n && !found;) {
                struct dirent64_ *d = (struct dirent64_ *)(buffer + at);
                at += d->reclen;
                const char *name = d->name;
                if ((name[0] == '.' && (!name[1] || (name[1] == '.' && !name[2]))) || union_hidden_name(name))
                    continue;
                if (i == __builtin_ctz(dirs)) { found = 1; break; }
                if (join(child, rel, len, "/", 1, name) < 0) continue;
                struct union_hit hit;
                if (walk(u, child, &hit, NULL, false) == 0 && hit.layer >= 0) found = 1;
            }
        }
        raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        if (found) return -ENOTEMPTY;
    }
    return 0;
}

/* Removes the whiteouts in the upper's directory rel (before rmdir). */
static void clear_markers(struct scratch *s, const struct union_view *u, const char *rel)
{
    char *path = s->list, *child = s->child;
    unsigned char *buffer = s->dents;
    if (join(path, u->layer[0], u->length[0], rel, strlen(rel), NULL) < 0) return;
    long fd = hs(__NR_openat, AT_FDCWD_, (long)path, O_RDONLY_ | O_DIRECTORY_ | O_CLOEXEC_, 0, 0, 0);
    if (fd < 0) return;
    for (int round = 0; round < 64; round++) {
        long n = raw_syscall(__NR_getdents64, fd, (long)buffer, sizeof(s->dents), 0, 0, 0);
        if (n <= 0) break;
        for (long at = 0; at < n;) {
            struct dirent64_ *d = (struct dirent64_ *)(buffer + at);
            at += d->reclen;
            if (union_hidden_name(d->name) && join(child, path, strlen(path), "/", 1, d->name) == 0)
                hs(__NR_unlinkat, AT_FDCWD_, (long)child, 0, 0, 0, 0);
        }
    }
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
}

static void forget_upper(const char *path)
{
    struct stat st;
    if (owners_enabled() && lstat_at(path, &st) == 0 &&
        ((st.st_mode & S_IFMT_) == S_IFDIR_ || st.st_nlink <= 1))
        owners_forget(&st);
}

static long remove_in(struct scratch *s, const struct union_view *u, const char *rel, bool dir)
{
    struct union_hit hit;
    long rc = walk(u, rel, &hit, NULL, true);
    if (rc < 0) return rc;
    if (hit.layer < 0) return hit.dirs ? -ENOTDIR : -ENOENT;
    if (dir && !hit.dir) return -ENOTDIR;
    if (!dir && hit.dir) return -EISDIR;
    char *path = s->a;
    if (join(path, u->layer[0], u->length[0], rel, strlen(rel), NULL) < 0) return -ENAMETOOLONG;
    if (dir) {
        rc = merged_empty(s, u, rel, hit.dirs);
        if (rc < 0) return rc;
        if (hit.dirs & 1u) {
            clear_markers(s, u, rel);
            forget_upper(path);
            rc = hs(__NR_unlinkat, AT_FDCWD_, (long)path, AT_REMOVEDIR_, 0, 0, 0);
            if (rc < 0) return rc;
        }
    } else if (hit.layer == 0) {
        forget_upper(path);
        rc = hs(__NR_unlinkat, AT_FDCWD_, (long)path, 0, 0, 0, 0);
        if (rc < 0) return rc;
    }
    if (!hit.below) return 0;
    rc = copy_parents(s, u, rel);
    return rc < 0 ? rc : make_whiteout(s, u, rel);
}

long union_remove(const struct union_view *u, const char *rel, bool dir)
{
    if (!rel[0]) return -EBUSY;
    struct scratch *s = scratch_get();
    if (!s) return -ENOMEM;
    long rc = remove_in(s, u, rel, dir);
    scratch_put(s);
    return rc;
}

static long rename_in(struct scratch *s, const struct union_view *u, const char *from, const char *to,
                      unsigned flags)
{
    struct union_hit src, dst;
    long rc = walk(u, from, &src, NULL, true);
    if (rc < 0) return rc;
    if (src.layer < 0) return src.dirs ? -ENOTDIR : -ENOENT;
    rc = walk(u, to, &dst, NULL, true);
    if (rc < 0) return rc;
    if (dst.layer < 0 && dst.dirs) return -ENOTDIR;
    if (!strcmp(from, to)) return 0;
    if (flags & RENAME_EXCHANGE_) {
        if (src.layer || src.below || dst.layer || dst.below) return -EXDEV;
    } else {
        if (src.dir && (src.layer > 0 || src.below)) return -EXDEV;
        if ((flags & RENAME_NOREPLACE_) && dst.layer >= 0) return -EEXIST;
        if (dst.layer >= 0) {
            if (src.dir && !dst.dir) return -ENOTDIR;
            if (!src.dir && dst.dir) return -EISDIR;
            if (dst.dir) {
                rc = merged_empty(s, u, to, dst.dirs);
                if (rc < 0) return rc;
            }
        }
    }
    char *a = s->a, *b = s->b;
    if (join(a, u->layer[0], u->length[0], from, strlen(from), NULL) < 0 ||
        join(b, u->layer[0], u->length[0], to, strlen(to), NULL) < 0)
        return -ENAMETOOLONG;
    if (src.layer > 0) {
        rc = copy_parents(s, u, from);
        if (!rc) rc = copy_one(s, u, src.layer, from, true);
        if (rc < 0) return rc;
    }
    rc = copy_parents(s, u, to);
    if (rc < 0) return rc;
    if (dst.whiteout && whiteout_path(u, to, s->w) == 0)
        hs(__NR_unlinkat, AT_FDCWD_, (long)s->w, 0, 0, 0, 0);
    if (dst.dir && (dst.dirs & 1u)) clear_markers(s, u, to);
    struct stat old;
    bool replaced = !(flags & RENAME_EXCHANGE_) && dst.layer == 0 && owners_enabled() &&
        lstat_at(b, &old) == 0;
    rc = hs(__NR_renameat2, AT_FDCWD_, (long)a, AT_FDCWD_, (long)b, flags, 0);
    if ((rc == -EINVAL || rc == -ENOSYS) && !flags)
        rc = hs(__NR_renameat, AT_FDCWD_, (long)a, AT_FDCWD_, (long)b, 0, 0);
    if (rc < 0) return rc;
    if (replaced && ((old.st_mode & S_IFMT_) == S_IFDIR_ || old.st_nlink <= 1)) owners_forget(&old);
    /* A directory moved over a hidden lower name must not show it. */
    if (src.dir && (dst.below || dst.whiteout)) union_make_opaque(u, to);
    if (src.below) return make_whiteout(s, u, from);
    return 0;
}

long union_rename(const struct union_view *u, const char *from, const char *to, unsigned flags)
{
    if (!from[0] || !to[0]) return -EBUSY;
    if (flags & ~(RENAME_NOREPLACE_ | RENAME_EXCHANGE_)) return -EINVAL;
    if (union_hidden_name(final_name(to)) && strlen(final_name(to)) >= 4) return -EPERM;
    struct scratch *s = scratch_get();
    if (!s) return -ENOMEM;
    long rc = rename_in(s, u, from, to, flags);
    scratch_put(s);
    return rc;
}

/* ---------------------------------------------------------------- listings */
/* A directory FD whose own layer is exhausted: the layers below follow.
 * The kernel answers the FD itself while it has entries; once it returns 0
 * the payload reads the next layer from a descriptor of its own. A rewind
 * (or a new FD at the same number) makes the kernel return entries again,
 * which resets the state. */
#define LISTINGS 16
struct listing {
    int fd;                    /* the guest's FD, -1 free */
    uint64_t dev, ino;         /* of the guest's directory */
    int layer;                 /* layer being read; u.count when done */
    int extra;                 /* our FD of that layer's directory, -1 none */
    uint64_t extra_dev, extra_ino;
    long emitted;              /* entries of that layer already read */
    uint32_t dirs;             /* layers that merge */
    char rel[CONFIG_MAX_PATH];
};
static struct listing listings[LISTINGS];
static uint32_t listing_lock;
static int listings_ready;

static void lock_listings(void)
{
    while (__atomic_exchange_n(&listing_lock, 1, __ATOMIC_ACQUIRE))
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
    if (!listings_ready) {
        for (int i = 0; i < LISTINGS; i++) { listings[i].fd = -1; listings[i].extra = -1; }
        listings_ready = 1;
    }
}
static void unlock_listings(void) { __atomic_store_n(&listing_lock, 0, __ATOMIC_RELEASE); }

static bool extra_valid(const struct listing *l)
{
    struct stat st;
    return l->extra >= 0 && raw_syscall(__NR_fstat, l->extra, (long)&st, 0, 0, 0, 0) == 0 &&
        st.st_dev == l->extra_dev && st.st_ino == l->extra_ino;
}

static void drop_extra(struct listing *l)
{
    if (extra_valid(l)) raw_syscall(__NR_close, l->extra, 0, 0, 0, 0, 0);
    l->extra = -1;
}

/* Removes whiteouts (and, below the top layer, names a higher layer shows
 * or hides) from a getdents64 batch in place. */
static long filter(const struct union_view *u, const struct listing *l, unsigned char *buffer, long n,
                   int layer, char *path)
{
    long out = 0;
    for (long at = 0; at < n;) {
        struct dirent64_ *d = (struct dirent64_ *)(buffer + at);
        unsigned short reclen = d->reclen;
        bool keep = !union_hidden_name(d->name);
        if (keep && layer > 0) {
            const char *name = d->name;
            if (name[0] == '.' && (!name[1] || (name[1] == '.' && !name[2]))) keep = false;
            size_t rl = strlen(l->rel);
            for (int j = 0; keep && j < layer; j++) {
                if (!(l->dirs & (1u << j))) continue;
                if (join(path, u->layer[j], u->length[j], l->rel, rl, "/") < 0 ||
                    strlen(path) + strlen(name) + 4 >= PATH_MAX)
                    break;
                size_t base = strlen(path);
                strcpy(path + base, name);
                if (exists(path)) { keep = false; break; }
                strcpy(path + base, ".wh.");
                strcpy(path + base + 4, name);
                if (exists(path)) keep = false;
            }
        }
        if (keep) {
            if (out != at) memmove(buffer + out, buffer + at, reclen);
            out += reclen;
        }
        at += reclen;
    }
    return out;
}

static long fd_host(int fd, char *host)
{
    char link[40] = "/proc/self/fd/";
    size_t at = strlen(link);
    char digits[12];
    int nd = 0;
    unsigned v = (unsigned)fd;
    do { digits[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (nd) link[at++] = digits[--nd];
    link[at] = 0;
    long n = hs(__NR_readlinkat, AT_FDCWD_, (long)link, (long)host, PATH_MAX - 1, 0, 0);
    if (n < 0) return n;
    host[n] = 0;
    return 0;
}

long union_getdents(int fd, void *buffer, unsigned long count, long ret)
{
    if (ret < 0) return ret;
    struct scratch *s = scratch_get();
    if (!s) return ret;
    int mount_count = mounts_enabled() ? mounts_snapshot(s->mounts, CONFIG_MAX_MOUNTS) : 0;
    int views = union_views(s->views, 1 + MOUNT_OVERLAYS, s->lowers, s->mounts, mount_count);
    char *host = s->list;
    const char *rel = "";
    int own = -1;
    int v = fd_host(fd, host) < 0 ? -1 : union_find(s->views, views, host, &own, &rel);
    if (v < 0) own = -1;
    const struct union_view *u = v < 0 ? NULL : &s->views[v];
    if (own < 0 || strlen(rel) >= CONFIG_MAX_PATH) { scratch_put(s); return ret; }
    struct stat st;
    if (raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0) < 0) { scratch_put(s); return ret; }
    lock_listings();
    struct listing *l = NULL, *spare = NULL;
    for (int i = 0; i < LISTINGS; i++) {
        if (listings[i].fd == fd && listings[i].dev == st.st_dev && listings[i].ino == st.st_ino) l = &listings[i];
        else if (listings[i].fd == fd || (!spare && listings[i].fd < 0)) spare = &listings[i];
    }
    if (ret > 0) {
        /* The FD's own layer: a fresh pass. */
        if (l) { drop_extra(l); l->fd = -1; }
        unlock_listings();
        for (;;) {
            struct listing top = {.dirs = 1u << own};
            long kept = filter(u, &top, buffer, ret, 0, NULL);
            if (kept > 0) { scratch_put(s); return kept; }
            ret = raw_syscall(__NR_getdents64, fd, (long)buffer, (long)count, 0, 0, 0);
            if (ret <= 0) break;
        }
        if (ret < 0) { scratch_put(s); return ret; }
        lock_listings();
        l = NULL;
    }
    if (!l) {
        if (!spare) spare = &listings[(unsigned long)fd % LISTINGS];
        if (spare->fd >= 0) drop_extra(spare);
        struct union_hit hit;
        if (walk(u, rel, &hit, NULL, false) < 0 || !hit.dir) { unlock_listings(); scratch_put(s); return 0; }
        l = spare;
        l->fd = fd;
        l->dev = st.st_dev;
        l->ino = st.st_ino;
        l->dirs = hit.dirs;
        l->extra = -1;
        l->emitted = 0;
        strcpy(l->rel, rel);
        l->layer = own + 1;
    }
    long result = 0;
    char *path = s->path;
    while (l->layer < u->count) {
        if (!(l->dirs & (1u << l->layer))) { l->layer++; continue; }
        if (!extra_valid(l)) {
            l->extra = -1;
            if (join(path, u->layer[l->layer], u->length[l->layer], l->rel, strlen(l->rel), NULL) < 0) {
                l->layer++;
                continue;
            }
            long dir = hs(__NR_openat, AT_FDCWD_, (long)path, O_RDONLY_ | O_DIRECTORY_ | O_CLOEXEC_, 0, 0, 0);
            if (dir < 0) { l->layer++; l->emitted = 0; continue; }
            long high = raw_syscall(__NR_fcntl, dir, F_DUPFD_CLOEXEC_, 700, 0, 0, 0);
            if (high >= 0) { raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0); dir = high; }
            struct stat ds;
            raw_syscall(__NR_fstat, dir, (long)&ds, 0, 0, 0, 0);
            l->extra = (int)dir;
            l->extra_dev = ds.st_dev;
            l->extra_ino = ds.st_ino;
            /* Reopened after the guest closed ours: skip what was read. */
            for (long skip = l->emitted; skip > 0;) {
                long n = raw_syscall(__NR_getdents64, dir, (long)buffer, (long)count, 0, 0, 0);
                if (n <= 0) break;
                for (long at = 0; at < n && skip > 0; skip--)
                    at += ((struct dirent64_ *)((unsigned char *)buffer + at))->reclen;
            }
        }
        long n = raw_syscall(__NR_getdents64, l->extra, (long)buffer, (long)count, 0, 0, 0);
        if (n < 0) { result = n; break; }
        if (n == 0) {
            drop_extra(l);
            l->layer++;
            l->emitted = 0;
            continue;
        }
        for (long at = 0; at < n; l->emitted++)
            at += ((struct dirent64_ *)((unsigned char *)buffer + at))->reclen;
        result = filter(u, l, buffer, n, l->layer, path);
        if (result > 0) break;
    }
    unlock_listings();
    scratch_put(s);
    return result;
}
