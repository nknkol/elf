/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Per-container shared state (container_state.h): the mount table of
 * emulated mounts (R4) with the /proc/<pid>/mounts and mountinfo views of
 * it, and the owner database (R5) that stat reports and chown/chmod and
 * file creation keep up to date. Both are mapped once per process, on
 * first use, from their inherited FDs. */
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "container_state.h"
#include "fake_ids.h"
#include "host_syscall.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#define PROT_READ_ 1
#define PROT_WRITE_ 2
#define MAP_SHARED_ 1
#define AT_FDCWD_ (-100)
#define S_IFMT_ 0170000
#define S_IFDIR_ 0040000
#define MS_RDONLY_ 1u
#define MS_NOSUID_ 2u
#define MS_NODEV_ 4u
#define MS_NOEXEC_ 8u

/* ---------------------------------------------------------------- mapping */
/* state: 0 not tried, 2 mapped, 3 failed (no retry). */
static void *map_shared(int fd, size_t size, int *state, void **slot)
{
    int s = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    if (s == 2)
        return __atomic_load_n(slot, __ATOMIC_ACQUIRE);
    if (s == 3 || fd < 0 || !size)
        return NULL;
    long p = raw_syscall(__NR_mmap, 0, (long)size, PROT_READ_ | PROT_WRITE_, MAP_SHARED_, fd, 0);
    if (p < 0 && p > -4096) {
        __atomic_store_n(state, 3, __ATOMIC_RELEASE);
        return NULL;
    }
    void *expected = NULL;
    if (!__atomic_compare_exchange_n(slot, &expected, (void *)p, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        raw_syscall(__NR_munmap, p, (long)size, 0, 0, 0, 0); /* a racing thread won */
        p = (long)expected;
    }
    __atomic_store_n(state, 2, __ATOMIC_RELEASE);
    return (void *)p;
}

/* A writer that died holding a lock must not stop the container: after a
 * long wait the lock is taken over. */
static void spin_lock(uint32_t *lock)
{
    for (unsigned long spins = 0;; spins++) {
        uint32_t free_value = 0;
        if (__atomic_compare_exchange_n(lock, &free_value, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            return;
        if (spins > 200000) {
            __atomic_store_n(lock, 1, __ATOMIC_SEQ_CST);
            return;
        }
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
    }
}
static void spin_unlock(uint32_t *lock) { __atomic_store_n(lock, 0, __ATOMIC_RELEASE); }

static void write_begin(uint32_t *lock, uint32_t *version)
{
    spin_lock(lock);
    __atomic_store_n(version, *version | 1, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
}
static void write_end(uint32_t *lock, uint32_t *version)
{
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(version, (*version | 1) + 1, __ATOMIC_RELEASE);
    spin_unlock(lock);
}
static uint32_t read_begin(const uint32_t *version)
{
    for (;;) {
        uint32_t v = __atomic_load_n(version, __ATOMIC_ACQUIRE);
        if (!(v & 1))
            return v;
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
    }
}
static int read_retry(const uint32_t *version, uint32_t v)
{
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return __atomic_load_n(version, __ATOMIC_RELAXED) != v;
}

static int path_under(const char *prefix, const char *path, int strict)
{
    size_t n = strlen(prefix);
    if (n == 1 && prefix[0] == '/')
        return strict ? path[1] != 0 : 1;
    if (strncmp(prefix, path, n))
        return 0;
    return path[n] == '/' || (!strict && !path[n]);
}

/* ---------------------------------------------------------------- mounts */
static int table_state;
static void *table_slot;

static struct mount_table *table(void)
{
    if (g_payload_config.mount_table_fd < 0)
        return NULL;
    return map_shared(g_payload_config.mount_table_fd, MOUNT_TABLE_SIZE, &table_state, &table_slot);
}

int mounts_enabled(void) { return g_payload_config.mount_table_fd >= 0; }

int mounts_snapshot(struct mount_entry *out, int max)
{
    struct mount_table *t = table();
    if (!t)
        return 0;
    for (;;) {
        uint32_t v = read_begin(&t->version);
        uint32_t count = __atomic_load_n(&t->count, __ATOMIC_RELAXED);
        if (count > MOUNT_TABLE_MAX) count = MOUNT_TABLE_MAX;
        int n = (int)count < max ? (int)count : max;
        for (int i = 0; i < n; i++)
            memcpy(&out[i], &t->entries[i], sizeof(out[i]));
        if (read_retry(&t->version, v))
            continue;
        for (int i = 0; i < n; i++) {
            out[i].guest[CONFIG_MAX_PATH - 1] = out[i].host[CONFIG_MAX_PATH - 1] = 0;
            out[i].source[sizeof(out[i].source) - 1] = out[i].fstype[sizeof(out[i].fstype) - 1] = 0;
            /* What the bridge accepts: absolute, canonical-looking. */
            if (out[i].guest[0] && (out[i].guest[0] != '/' || out[i].host[0] != '/' || !out[i].guest[1]))
                out[i].guest[0] = 0;
        }
        return n;
    }
}

int mounts_access(char *out, int max)
{
    struct mount_table *t = table();
    if (!t)
        return 0;
    for (;;) {
        uint32_t v = read_begin(&t->version);
        uint32_t count = __atomic_load_n(&t->count, __ATOMIC_RELAXED);
        int n = (int)(count > MOUNT_TABLE_MAX ? MOUNT_TABLE_MAX : count);
        if (n > max) n = max;
        for (int i = 0; i < n; i++)
            out[i] = t->entries[i].guest[0] ? (char)t->entries[i].access : 'd';
        if (!read_retry(&t->version, v))
            return n;
    }
}

int mounts_hidden(const struct mount_entry *e, int count, int i)
{
    if (!e[i].guest[0])
        return 1;
    for (int j = 0; j < count; j++)
        if (j != i && e[j].guest[0] && e[j].id > e[i].id && path_under(e[j].guest, e[i].guest, 0))
            return 1;
    return 0;
}

int mounts_bind_hidden(const struct mount_entry *e, int count, const char *guest)
{
    for (int j = 0; j < count; j++)
        if (e[j].guest[0] && path_under(e[j].guest, guest, 0))
            return 1;
    return 0;
}

int mounts_find(const struct mount_entry *e, int count, const char *guest)
{
    int found = -1;
    for (int i = 0; i < count; i++)
        if (e[i].guest[0] && !strcmp(e[i].guest, guest) && (found < 0 || e[i].id > e[found].id))
            found = i;
    return found;
}

long mounts_add(const struct mount_entry *entry)
{
    struct mount_table *t = table();
    if (!t)
        return -ENOSYS;
    write_begin(&t->lock, &t->version);
    uint32_t count = t->count > MOUNT_TABLE_MAX ? MOUNT_TABLE_MAX : t->count;
    uint32_t slot = 0;
    while (slot < count && t->entries[slot].guest[0])
        slot++;
    long rc = -ENOMEM;
    if (slot < MOUNT_TABLE_MAX) {
        struct mount_entry *e = &t->entries[slot];
        memcpy(e, entry, sizeof(*e));
        e->id = ++t->next_id;
        if (slot == count)
            t->count = count + 1;
        rc = 0;
    }
    write_end(&t->lock, &t->version);
    return rc;
}

long mounts_remove(const char *guest, int detach)
{
    struct mount_table *t = table();
    if (!t)
        return -EINVAL;
    write_begin(&t->lock, &t->version);
    int count = t->count > MOUNT_TABLE_MAX ? MOUNT_TABLE_MAX : (int)t->count;
    int found = mounts_find(t->entries, count, guest);
    long rc = found < 0 ? -EINVAL : 0;
    /* Mounts below it (newer ones; older ones are hidden by it anyway). */
    for (int i = 0; !rc && i < count; i++)
        if (i != found && t->entries[i].guest[0] && t->entries[i].id > t->entries[found].id &&
            path_under(guest, t->entries[i].guest, 1)) {
            if (!detach)
                rc = -EBUSY;
        }
    if (!rc) {
        uint32_t id = t->entries[found].id;
        for (int i = 0; detach && i < count; i++)
            if (i != found && t->entries[i].guest[0] && t->entries[i].id > id &&
                path_under(guest, t->entries[i].guest, 1))
                t->entries[i].guest[0] = 0;
        t->entries[found].guest[0] = 0;
        while (t->count && !t->entries[t->count - 1].guest[0])
            t->count--;
    }
    write_end(&t->lock, &t->version);
    return rc;
}

long mounts_set_flags(const char *guest, uint32_t flags, uint32_t access)
{
    struct mount_table *t = table();
    if (!t)
        return -EINVAL;
    write_begin(&t->lock, &t->version);
    int count = t->count > MOUNT_TABLE_MAX ? MOUNT_TABLE_MAX : (int)t->count;
    int found = mounts_find(t->entries, count, guest);
    if (found >= 0) {
        t->entries[found].flags = flags;
        t->entries[found].access = access;
    }
    write_end(&t->lock, &t->version);
    return found < 0 ? -EINVAL : 0;
}

long mounts_move(const char *from, const char *to)
{
    struct mount_table *t = table();
    if (!t)
        return -EINVAL;
    size_t from_len = strlen(from), to_len = strlen(to);
    write_begin(&t->lock, &t->version);
    int count = t->count > MOUNT_TABLE_MAX ? MOUNT_TABLE_MAX : (int)t->count;
    int found = mounts_find(t->entries, count, from);
    long rc = found < 0 ? -EINVAL : 0;
    for (int i = 0; !rc && i < count; i++)
        if (t->entries[i].guest[0] && path_under(from, t->entries[i].guest, 0) &&
            strlen(t->entries[i].guest) - from_len + to_len >= CONFIG_MAX_PATH)
            rc = -ENAMETOOLONG;
    uint32_t id = found >= 0 ? t->entries[found].id : 0;
    for (int i = 0; !rc && i < count; i++) {
        struct mount_entry *e = &t->entries[i];
        if (!e->guest[0] || !path_under(from, e->guest, 0) || (i != found && e->id < id))
            continue;
        char moved[CONFIG_MAX_PATH];
        strcpy(moved, to_len == 1 && e->guest[from_len] ? "" : to);
        strcat(moved, e->guest + from_len);
        strcpy(e->guest, moved);
    }
    write_end(&t->lock, &t->version);
    return rc;
}

/* ---- /proc/<pid>/mounts and mountinfo ---- */
struct out { int fd; long error; size_t used; char buffer[1024]; };

static void flush(struct out *o)
{
    size_t done = 0;
    while (done < o->used && !o->error) {
        long n = raw_syscall(__NR_write, o->fd, (long)o->buffer + done, (long)(o->used - done), 0, 0, 0);
        if (n <= 0) o->error = n ? n : -EIO;
        else done += (size_t)n;
    }
    o->used = 0;
}
static void put(struct out *o, const char *s)
{
    for (; *s; s++) {
        if (o->used == sizeof(o->buffer)) flush(o);
        o->buffer[o->used++] = *s;
    }
}
/* Spaces and the like as the kernel escapes them (\040). */
static void put_path(struct out *o, const char *s)
{
    char esc[5] = {'\\', 0, 0, 0, 0};
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\\') {
            esc[1] = (char)('0' + (c >> 6));
            esc[2] = (char)('0' + ((c >> 3) & 7));
            esc[3] = (char)('0' + (c & 7));
            put(o, esc);
        } else {
            char one[2] = {(char)c, 0};
            put(o, one);
        }
    }
}
static void put_number(struct out *o, unsigned long v)
{
    char digits[24];
    int n = 0;
    do digits[n++] = (char)('0' + v % 10); while ((v /= 10) && n < 23);
    char text[24];
    for (int i = 0; i < n; i++) text[i] = digits[n - 1 - i];
    text[n] = 0;
    put(o, text);
}

const char *mounts_fs_name(const char *host)
{
    static const struct { unsigned long magic; const char *name; } names[] = {
        {0x9fa0, "proc"}, {0x62656572, "sysfs"}, {0x01021994, "tmpfs"}, {0x1cd1, "devpts"},
        {0xef53, "ext4"}, {0xf2f52010, "f2fs"}, {0x65735546, "fuse"}, {0x858458f6, "ramfs"},
        {0x63677270, "cgroup2"}, {0x27e0eb, "cgroup"}, {0x19800202, "mqueue"},
        {0x73636673, "securityfs"}, {0x64626720, "debugfs"}, {0x74726163, "tracefs"},
        {0xe0f5e1e2, "erofs"}, {0x6e736673, "nsfs"}, {0x5346414f, "afs"}, {0x2011bab0, "exfat"},
        {0x4d44, "vfat"}, {0x794c7630, "overlay"}, {0x58465342, "xfs"}, {0x9123683e, "btrfs"},
    };
    unsigned long buffer[16];
    if (host_syscall(__NR_statfs, (long)host, (long)buffer, 0, 0, 0, 0) < 0)
        return "none";
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if ((buffer[0] & 0xffffffffu) == names[i].magic)
            return names[i].name;
    return "none";
}

/* One line: what every format needs of a mount. */
struct row {
    const char *guest, *host, *source, *fstype;
    uint32_t flags;
    int id, parent;
};

static void put_options(struct out *o, uint32_t flags)
{
    put(o, flags & MS_RDONLY_ ? "ro" : "rw");
    if (flags & MS_NOSUID_) put(o, ",nosuid");
    if (flags & MS_NODEV_) put(o, ",nodev");
    if (flags & MS_NOEXEC_) put(o, ",noexec");
    put(o, ",relatime");
}

static void put_row(struct out *o, const struct row *r, int info)
{
    if (!info) {
        put_path(o, r->source);
        put(o, " ");
        put_path(o, r->guest);
        put(o, " ");
        put_path(o, r->fstype);
        put(o, " ");
        put_options(o, r->flags);
        put(o, " 0 0\n");
        return;
    }
    struct stat st;
    unsigned long dev = host_syscall(__NR_newfstatat, AT_FDCWD_, (long)r->host, (long)&st, 0, 0, 0) ? 0 : st.st_dev;
    put_number(o, (unsigned long)r->id);
    put(o, " ");
    put_number(o, (unsigned long)r->parent);
    put(o, " ");
    put_number(o, ((dev >> 8) & 0xfff) | ((dev >> 32) & ~0xffful));
    put(o, ":");
    put_number(o, (dev & 0xff) | ((dev >> 12) & ~0xfful));
    put(o, " / ");
    put_path(o, r->guest);
    put(o, " ");
    put_options(o, r->flags);
    put(o, " - ");
    put_path(o, r->fstype);
    put(o, " ");
    put_path(o, r->source);
    put(o, r->flags & MS_RDONLY_ ? " ro\n" : " rw\n");
}

#define ROWS (1 + CONFIG_MAX_BINDS + MOUNT_TABLE_MAX)
struct render_scratch {
    struct mount_entry entries[MOUNT_TABLE_MAX];
    struct row rows[ROWS];
    char fstypes[1 + CONFIG_MAX_BINDS][16];
    struct out out;
};

long mounts_render(int fd, int info)
{
    long mem = raw_syscall(__NR_mmap, 0, sizeof(struct render_scratch), 3, 0x22, -1, 0);
    if (mem < 0 && mem > -4096)
        return mem;
    struct render_scratch *s = (void *)mem;
    payload_config_t *cfg = &g_payload_config;
    int count = mounts_snapshot(s->entries, MOUNT_TABLE_MAX), rows = 0;
    const char *root = cfg->root[0] ? cfg->root : "/";
    uint32_t root_flags = 0;
#ifdef GUARDED
    if (cfg->mount_access_observe[0] == 'r' && cfg->guard >= GUARD_PATHS)
        root_flags = MS_RDONLY_;
#endif
    s->rows[rows++] = (struct row){"/", root, "overlay", "overlay", root_flags, 20, 1};
    for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
        const char *host = cfg->binds[i].dst;
        strcpy(s->fstypes[i], mounts_fs_name(host));
        uint32_t flags = 0;
#ifdef GUARDED
        if (cfg->mount_access_observe[i + 1] == 'r' && cfg->guard >= GUARD_PATHS)
            flags = MS_RDONLY_;
#endif
        const char *fstype = s->fstypes[i];
        s->rows[rows++] = (struct row){cfg->binds[i].src, host,
                                       !strcmp(fstype, "proc") || !strcmp(fstype, "sysfs") ||
                                       !strcmp(fstype, "devpts") || !strcmp(fstype, "tmpfs") ?
                                       fstype : "/dev/root", fstype, flags, 21 + i, 0};
    }
    /* Emulated mounts in creation order. */
    for (uint32_t last = 0;;) {
        int next = -1;
        for (int i = 0; i < count; i++)
            if (s->entries[i].guest[0] && s->entries[i].id > last &&
                (next < 0 || s->entries[i].id < s->entries[next].id))
                next = i;
        if (next < 0)
            break;
        const struct mount_entry *e = &s->entries[next];
        last = e->id;
        s->rows[rows++] = (struct row){e->guest, e->host, e->source[0] ? e->source : "none",
                                       e->fstype[0] ? e->fstype : "none", e->flags,
                                       21 + CONFIG_MAX_BINDS + next, 0};
    }
    /* mountinfo parents: the newest earlier row whose mountpoint covers it. */
    for (int i = 1; i < rows; i++) {
        s->rows[i].parent = s->rows[0].id;
        for (int j = i - 1; j >= 0; j--)
            if (path_under(s->rows[j].guest, s->rows[i].guest, 1)) {
                s->rows[i].parent = s->rows[j].id;
                break;
            }
    }
    s->out.fd = fd;
    s->out.error = 0;
    s->out.used = 0;
    for (int i = 0; i < rows; i++)
        put_row(&s->out, &s->rows[i], info);
    flush(&s->out);
    long rc = s->out.error;
    raw_syscall(__NR_munmap, mem, sizeof(struct render_scratch), 0, 0, 0, 0);
    return rc;
}

/* ---------------------------------------------------------------- owners */
static int db_state;
static void *db_slot;
static size_t db_size;

static struct owner_db_header *db(void)
{
    int fd = g_payload_config.owner_db_fd;
    if (fd < 0)
        return NULL;
    if (__atomic_load_n(&db_state, __ATOMIC_ACQUIRE) == 2)
        return __atomic_load_n(&db_slot, __ATOMIC_ACQUIRE);
    struct stat st;
    if (raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0) < 0 || st.st_size < (long)sizeof(struct owner_db_header)) {
        __atomic_store_n(&db_state, 3, __ATOMIC_RELEASE);
        return NULL;
    }
    db_size = (size_t)st.st_size;
    struct owner_db_header *h = map_shared(fd, db_size, &db_state, &db_slot);
    if (!h)
        return NULL;
    uint32_t cap = h->capacity;
    if (strncmp(h->magic, OWNER_DB_MAGIC, 8) || !cap || (cap & (cap - 1)) ||
        sizeof(*h) + (size_t)cap * sizeof(struct owner_record) > db_size) {
        __atomic_store_n(&db_state, 3, __ATOMIC_RELEASE);
        return NULL;
    }
    return h;
}

int owners_enabled(void) { return g_payload_config.owner_db_fd >= 0; }

static struct owner_record *records(struct owner_db_header *h)
{
    return (struct owner_record *)(h + 1);
}

/* The live record of (dev, ino), or where to insert it (*slot; -1 when the
 * table is full). Caller reads under a version or holds the lock. */
static struct owner_record *probe(struct owner_db_header *h, uint64_t dev, uint64_t ino, long *slot)
{
    uint32_t mask = h->capacity - 1;
    struct owner_record *r = records(h);
    long free_slot = -1;
    uint32_t at = (uint32_t)owner_hash(dev, ino) & mask;
    for (uint32_t n = 0; n <= mask; n++, at = (at + 1) & mask) {
        uint32_t flags = r[at].flags;
        if (!flags) {
            if (free_slot < 0) free_slot = at;
            break;
        }
        if (flags & OWNER_DEAD) {
            if (free_slot < 0) free_slot = at;
            continue;
        }
        if (r[at].dev == dev && r[at].ino == ino) {
            if (slot) *slot = at;
            return &r[at];
        }
    }
    if (slot) *slot = free_slot;
    return NULL;
}

static int find(const struct stat *st, struct owner_record *out)
{
    struct owner_db_header *h = db();
    if (!h)
        return 0;
    for (;;) {
        uint32_t v = read_begin(&h->version);
        struct owner_record *r = probe(h, st->st_dev, st->st_ino, NULL);
        int hit = r != NULL;
        if (hit) memcpy(out, r, sizeof(*out));
        if (!read_retry(&h->version, v))
            return hit;
    }
}

/* Sets (flags: OWNER_IDS/OWNER_MODE parts given) or clears parts of the
 * record of st; a record left with nothing is deleted. */
static long update(const struct stat *st, uint32_t set, uint32_t clear,
                   uint32_t uid, uint32_t gid, uint32_t mode)
{
    struct owner_db_header *h = db();
    if (!h)
        return 0;
    long rc = 0, slot;
    write_begin(&h->lock, &h->version);
    struct owner_record *r = probe(h, st->st_dev, st->st_ino, &slot);
    if (!r && set) {
        struct owner_record *all = records(h);
        if (slot < 0 || (!all[slot].flags && (h->count + 1) * 8ull > h->capacity * 7ull)) {
            rc = -ENOSPC;
        } else {
            if (!all[slot].flags)
                h->count++;
            r = &all[slot];
            r->dev = st->st_dev;
            r->ino = st->st_ino;
            r->uid = r->gid = r->mode = 0;
            r->flags = OWNER_USED;
        }
    }
    if (r) {
        r->flags &= ~clear;
        if (set & OWNER_IDS) { r->uid = uid; r->gid = gid; }
        if (set & OWNER_MODE) r->mode = mode & 07777;
        r->flags |= set;
        if (!(r->flags & (OWNER_IDS | OWNER_MODE)))
            r->flags = OWNER_DEAD;
    }
    write_end(&h->lock, &h->version);
    return rc;
}

void owners_lookup(const struct stat *st, uint32_t *uid, uint32_t *gid, uint32_t *mode)
{
    struct owner_record r;
    int hit = find(st, &r);
    *uid = hit && (r.flags & OWNER_IDS) ? r.uid : fake_ids_host_owned(st->st_uid, 0) ? 0 : st->st_uid;
    *gid = hit && (r.flags & OWNER_IDS) ? r.gid : fake_ids_host_owned(st->st_gid, 1) ? 0 : st->st_gid;
    *mode = hit && (r.flags & OWNER_MODE) ? r.mode : st->st_mode & 07777;
}

void owners_stat(long number, const long *a)
{
    if (!owners_enabled() || !db())
        return;
    struct stat st;
    unsigned char *buffer;
    if (number == __NR_fstat || number == __NR_newfstatat) {
        buffer = (unsigned char *)(number == __NR_fstat ? a[1] : a[2]);
        if (!buffer) return;
        memcpy(&st, buffer, sizeof(st));
    } else if (number == __NR_statx) {
        buffer = (unsigned char *)a[4];
        if (!buffer) return;
        uint32_t mask, major, minor;
        memcpy(&mask, buffer, 4);
        if (!(mask & 0x100 /* STATX_INO */)) return;
        memcpy(&st.st_ino, buffer + 32, 8);
        memcpy(&major, buffer + 136, 4);
        memcpy(&minor, buffer + 140, 4);
        st.st_dev = (minor & 0xff) | ((unsigned long)major << 8) | ((unsigned long)(minor & ~0xffu) << 12);
    } else {
        return;
    }
    struct owner_record r;
    if (!find(&st, &r))
        return;
    if (number == __NR_statx) {
        uint16_t m;
        memcpy(&m, buffer + 28, 2);
        if (r.flags & OWNER_IDS) { memcpy(buffer + 20, &r.uid, 4); memcpy(buffer + 24, &r.gid, 4); }
        if (r.flags & OWNER_MODE) { m = (uint16_t)((m & S_IFMT_) | (r.mode & 07777)); memcpy(buffer + 28, &m, 2); }
    } else {
        struct stat *out = (struct stat *)buffer;
        if (r.flags & OWNER_IDS) { out->st_uid = r.uid; out->st_gid = r.gid; }
        if (r.flags & OWNER_MODE) out->st_mode = (out->st_mode & S_IFMT_) | (r.mode & 07777);
    }
}

static int in_groups(uint32_t gid)
{
    uint32_t groups[32];
    int n = fake_ids_groups(groups);
    if (gid == fake_ids_effective(1) || gid == fake_ids_fs(1))
        return 1;
    for (int i = 0; i < n; i++)
        if (groups[i] == gid) return 1;
    return 0;
}

long owners_chown(const struct stat *st, long uid, long gid)
{
    if (!db())
        return -EIO;
    uint32_t cur_uid, cur_gid, mode;
    owners_lookup(st, &cur_uid, &cur_gid, &mode);
    uint32_t new_uid = uid == -1 || (uint32_t)uid == 0xffffffffu ? cur_uid : (uint32_t)uid;
    uint32_t new_gid = gid == -1 || (uint32_t)gid == 0xffffffffu ? cur_gid : (uint32_t)gid;
    /* Linux: only the owner may change the group (to one of its own); only
     * a privileged caller may give a file away. */
    if (!fake_ids_privileged() &&
        (new_uid != cur_uid || (new_gid != cur_gid && (fake_ids_fs(0) != cur_uid || !in_groups(new_gid)))))
        return -EPERM;
    if (!new_uid && !new_gid)
        return update(st, 0, OWNER_IDS, 0, 0, 0);
    return update(st, OWNER_IDS, 0, new_uid, new_gid, 0);
}

long owners_may_chmod(const struct stat *st)
{
    if (fake_ids_privileged())
        return 0;
    uint32_t uid, gid, mode;
    owners_lookup(st, &uid, &gid, &mode);
    return uid == fake_ids_fs(0) ? 0 : -EPERM;
}

unsigned owners_host_mode(const struct stat *st, unsigned mode)
{
    return (mode & 07777) | ((st->st_mode & S_IFMT_) == S_IFDIR_ ? 0700 : 0600);
}

void owners_chmod_done(const struct stat *st, unsigned mode, unsigned host_mode)
{
    if ((mode & 07777) == (host_mode & 07777))
        update(st, 0, OWNER_MODE, 0, 0, 0);
    else
        update(st, OWNER_MODE, 0, 0, 0, mode);
}

void owners_created(const struct stat *st)
{
    if (!db())
        return;
    uint32_t uid = fake_ids_fs(0), gid = fake_ids_fs(1);
    /* A reused inode number must not keep a deleted file's record. */
    update(st, uid || gid ? OWNER_IDS : 0, OWNER_IDS | OWNER_MODE, uid, gid, 0);
}

void owners_forget(const struct stat *st)
{
    if (db())
        update(st, 0, OWNER_IDS | OWNER_MODE, 0, 0, 0);
}
