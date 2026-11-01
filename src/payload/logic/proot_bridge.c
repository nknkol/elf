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
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include "config.h"
#include "syscall_nums.h"
#include "proot_bridge.h"
#include "fake_ids.h"
#include "container_state.h"
#include "union_view.h"
#include "net_view.h"
#ifdef GUARDED
#include "fd_runtime.h"
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
/* Host path calls go through the broker in isolation mode. */
#include "host_syscall.h"
#include "broker_proto.h"
#define raw_syscall host_syscall
static int loop_device(const char *guest); /* (R6 loop devices, below) */
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

#define BRIDGE_FRAMES 6
#define LINK_HINTS 8
struct link_hints {
    int count;
    char path[LINK_HINTS][PATH_MAX], target[LINK_HINTS][PATH_MAX];
};

typedef struct {
    BindingTable table;
    bool mutation;
    bool traverse; /* Final ancestor-only paths are acceptable for this call. */
    bool follow_final; /* Resolution dereferences a final symlink. */
    bool attributes; /* The call changes metadata of an existing name. */
    bool creates; /* The call creates a new name (EEXIST if it exists). */
    /* Skip the final lstat: the call itself detects a final symlink
     * (open with O_NOFOLLOW, ELOOP) and is then resolved again. */
    bool defer_final;
    /* The final lstat of a followed resolution found no symlink: that is
     * the stat result for the same host path (saves one host walk). */
    bool final_valid;
    /* final_stat describes the object b->host names (checked before the
     * guarded walk rewrites b->host; the walk pins that same inode). */
    bool final_match;
    struct stat final_stat;
    /* Isolation mode: every host lookup is a round trip to the broker.
     * Optimistic resolution skips them and maps the guest path lexically;
     * the broker then refuses (ELOOP) any symlink on the way, and the call
     * is run again with full resolution. Allowed for the first attempt of
     * a call; used once a resolution actually skipped lookups. */
    bool optimistic_allowed, optimistic, optimistic_used, force_full;
    /* Symlinks the broker reported in earlier attempts of this call: an
     * optimistic lookup of such a host path is a symlink, read from here. */
    const struct link_hints *hints;
    /* Guarded modes: the final call goes through a directory descriptor
     * walked component by component without following symlinks, so a
     * component swapped for a symlink after resolution cannot redirect it. */
    bool secure;
    int walk_fd[4], walk_count;
#ifdef GUARDED
    bool reads; /* Immutable read policy snapshot below is active. */
    enum fs_access access[CONFIG_MOUNT_IDS];
    struct fs_policy policy;
    const char *exposed[CONFIG_MOUNT_IDS];
    size_t exposed_count;
    /* Private getdents64 bounce: hidden names never reach guest memory. */
    unsigned char dirents[4096];
    char classified[PATH_MAX];
#endif
    const struct proot_path_context *context;
    int anchor_fd;
    struct proot_open_origin anchor;
    PathBinding bindings[CONFIG_MOUNT_IDS - 1];
    /* R4: the mount table as this call sees it (bindings point into it). */
    struct mount_entry mounts[CONFIG_MAX_MOUNTS];
    int mount_count;
    char cwd[PATH_MAX], guest[PATH_MAX], host[PATH_MAX];
    char first_guest[PATH_MAX], first_host[PATH_MAX];
    struct sockaddr_un address;
    struct guest_msghdr message;
    /* /proc link emulation: never the first_* pair a caller may hold. */
    char proc_guest[PATH_MAX], proc_host[PATH_MAX], proc_link_host[PATH_MAX];
    char proc_data[8192]; /* A loader-run process's kernel cmdline. */
    char proc_candidate[PATH_MAX];
    /* Path walking scratch kept off the guest stack: a vfork child may run
     * on a small spawn stack (glibc posix_spawn gives about 36 KiB), and
     * each followed symlink would otherwise cost 8 KiB of it. Deeper
     * chains use deep_frames, mapped on first use and kept with the bridge. */
    PathFrame path_frames[BRIDGE_FRAMES];
    PathFrame *deep_frames;
    char resolve_scratch[2][PATH_MAX];
    char fd_host[PATH_MAX], mapped[PATH_MAX], final_host[PATH_MAX];
    /* R6: the root's merged view (union_view.h). union_op says what the
     * call does to its resolved name; resolution leaves the name's layer
     * and path relative to the layers in union_layer/union_rel (layer -1:
     * not in the view). */
    struct union_view views[1 + MOUNT_OVERLAYS];
    int view_count;
    const struct union_view *uv, *first_uv; /* the view of union_rel, first_union_rel */
    const struct union_view *map_view, *final_view; /* of the last mapping, of the resolution */
    bool root_union; /* views[0] is the root's */
    char overlay_lowers[MOUNT_OVERLAYS * CONFIG_MAX_LOWERS][CONFIG_MAX_PATH];
    bool union_on;
    int union_op;
    long open_flags;
    bool union_opaque;
    int union_layer, first_union_layer;
    struct union_memo umemo;
    char union_rel[PATH_MAX], first_union_rel[PATH_MAX], union_named[PATH_MAX];
} Bridge;

enum { UOP_READ, UOP_COPY, UOP_RECORD, UOP_CREATE, UOP_OPEN };

/* The view holding a host path (union_find), NULL if none. */
static const struct union_view *bridge_view(Bridge *b, const char *host, int *layer, const char **rel)
{
    int v = union_find(b->views, b->view_count, host, layer, rel);
    return v < 0 ? NULL : &b->views[v];
}

/* A path in the root's lower layers as the root's upper names it; 1 if
 * rewritten. (The lowerdirs of an overlay mount are guest directories of
 * their own, named as such.) */
static int bridge_alias(Bridge *b, const char *host, char *out)
{
    return b->root_union ? union_alias(&b->views[0], host, out) : 0;
}

/* The view whose upper holds host (the longest), NULL if none. */
static const struct union_view *upper_view(Bridge *b, const char *host)
{
    const struct union_view *best = NULL;
    for (int v = 0; v < b->view_count; v++) {
        const struct union_view *u = &b->views[v];
        size_t n = u->length[0];
        if (!strncmp(host, u->layer[0], n) && (host[n] == 0 || host[n] == '/') &&
            (!best || n > best->length[0]))
            best = u;
    }
    return best;
}

size_t proot_bridge_scratch_size(void) { return sizeof(Bridge); }

/* A free or hidden mount slot: a prefix no path has. */
static const char UNMOUNTED[] = "/\001elf-unmounted";

/* A case variant of a marked mountpoint names it on this host storage: use
 * its exact spelling, so mount selection and policy see the same object. */
static void respell(void *opaque, char *path)
{
    Bridge *b = opaque;
    for (size_t i = 0; i < b->table.count && i < (size_t)g_payload_config.bind_count; i++) {
        const PathBinding *e = &b->table.entries[i];
        uint32_t fold = g_payload_config.binds[i].fold;
        if (!fold || e->guest == UNMOUNTED) continue;
        size_t from = fold - 1, n = strlen(e->guest), k = from;
        if (strncmp(path, e->guest, from)) continue;
        for (; k < n; k++) {
            char x = path[k], y = e->guest[k];
            if (x >= 'A' && x <= 'Z') x |= 0x20;
            if (y >= 'A' && y <= 'Z') y |= 0x20;
            if (x != y) break;
        }
        if (k == n && (path[n] == '\0' || path[n] == '/'))
            memcpy(path + from, e->guest + from, n - from);
    }
}

#define DEEP_FRAMES_SIZE ((CANON_LEVELS - BRIDGE_FRAMES) * sizeof(PathFrame))
static PathFrame *deep_frames(void *opaque)
{
    Bridge *b = opaque;
    if (!b->deep_frames) {
        long mem = raw_syscall(__NR_mmap, 0, DEEP_FRAMES_SIZE, 3, 0x22, -1, 0);
        if ((unsigned long)mem >= (unsigned long)-4095)
            return NULL;
        b->deep_frames = (PathFrame *)mem;
    }
    return b->deep_frames;
}

static int host_map(void *opaque, const char *guest, char *host)
{
    Bridge *b = opaque;
    int rc = binding_table_map(&b->table, GUEST, guest, host);
    /* R6: a name in the root's layers (through the root or a bind made of
     * it) is shown by the topmost layer that has it. */
    if (rc >= 0 && b->union_on) {
        if (bridge_alias(b, host, b->mapped)) strcpy(host, b->mapped);
        const struct union_view *view = upper_view(b, host);
        b->map_view = view;
        int u = view ? union_map(view, host, NULL, &b->umemo) : 0;
        if (u < 0) return u;
    }
    return rc;
}

#ifdef GUARDED
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
            long ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->proc_host, (long)&st, 0, 0, 0);
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
        bool directory = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->table.entries[i].host,
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
                    ret = raw_syscall(__NR_openat, AT_FDCWD, (long)path,
                                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444, 0, 0);
                    if (ret >= 0) ret = raw_syscall(__NR_close, ret, 0, 0, 0, 0, 0);
                } else {
                    ret = raw_syscall(__NR_mkdirat, AT_FDCWD, (long)path, 0755, 0, 0, 0);
                }
                if (ret == -EEXIST) ret = 0;
            } else if (op == 3) {
                raw_syscall(__NR_unlinkat, AT_FDCWD, (long)path,
                            leaf && !directory ? 0 : AT_REMOVEDIR, 0, 0, 0);
            } else if (!leaf || directory) {
                ret = raw_syscall(__NR_fchmodat, AT_FDCWD, (long)path, op == 1 ? 0555 : 0700, 0, 0, 0);
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
    return !raw_syscall(__NR_newfstatat, AT_FDCWD, (long)path, (long)&st, AT_SYMLINK_NOFOLLOW, 0, 0) &&
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
    if (raw_syscall(__NR_mkdirat, AT_FDCWD, (long)temp, 0700, 0, 0, 0) < 0) {
        __atomic_store_n(&glue_state, state, __ATOMIC_RELEASE);
        return state;
    }
    struct stat st;
    long owner = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)temp, (long)&st,
                             AT_SYMLINK_NOFOLLOW, 0, 0) ? -1 : (long)st.st_uid;
    if (glue_valid(name, owner)) {
        raw_syscall(__NR_unlinkat, AT_FDCWD, (long)temp, AT_REMOVEDIR, 0, 0, 0);
        __atomic_store_n(&glue_state, 1, __ATOMIC_RELEASE);
        return 1;
    }
    if (!glue_walk(b, temp, 0) && !glue_walk(b, temp, 1) &&
        !raw_syscall(__NR_fchmodat, AT_FDCWD, (long)temp, 0555, 0, 0, 0)) {
        if (!raw_syscall(__NR_renameat2, AT_FDCWD, (long)temp, AT_FDCWD, (long)name, 0, 0))
            state = 1;
        else if (glue_valid(name, owner))
            state = 1;
    }
    if (glue_valid(temp, owner) || state < 0) {
        /* Unpublished: undo the private copy. */
        raw_syscall(__NR_fchmodat, AT_FDCWD, (long)temp, 0700, 0, 0, 0);
        glue_walk(b, temp, 2);
        glue_walk(b, temp, 3);
        raw_syscall(__NR_unlinkat, AT_FDCWD, (long)temp, AT_REMOVEDIR, 0, 0, 0);
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
#ifdef GUARDED
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
    /* The broker checks the lexical result for symlinks itself, from the
     * mount's root: ancestors of a nested mount point stay real lookups. */
    if (b->optimistic && (!strcmp(guest, "/") || !glue_ancestor(b, guest))) {
        for (int i = 0; b->hints && i < b->hints->count; i++)
            if (!strcmp(b->hints->path[i], host))
                return 1;
        return 0;
    }
    /* Each host lstat walks the whole host path, which dominates path calls.
     * Skip it where the answer cannot change resolution: a non-followed final
     * name (an existing link stays a link; a missing one is fine), and the
     * root or a bind mount point, whose configured host path the kernel
     * follows itself rather than PRoot reinterpreting it as a guest link. */
    if (finality == FINAL_NORMAL && (!b->follow_final || b->defer_final))
        return 0;
    if (!strcmp(guest, "/"))
        return 0;
    for (size_t i = 0; i < b->table.count; i++)
        if (!strcmp(guest, b->table.entries[i].guest))
            return 0;
    struct stat st;
    long ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)host, (long)&st,
                          AT_SYMLINK_NOFOLLOW, 0, 0);
    /* A missing directory on the way to a bind is glue, not ENOENT. */
    if (ret == -ENOENT && glue_ancestor(b, guest))
        return 0;
    /* HarmonyOS refuses lstat on many system library links while readlink
     * works: readlink tells a link from anything else. */
    if (ret == -EACCES) {
        char probe[1];
        long link = raw_syscall(__NR_readlinkat, AT_FDCWD, (long)host, (long)probe, 1, 0, 0);
        if (link >= 0)
            return 1;
        if (link == -EINVAL)
            return 0;
    }
    if (ret < 0)
        return IS_FINAL(finality) ? 0 : (int)ret;
    unsigned int type = st.st_mode & S_IFMT;
    if (!IS_FINAL(finality) && type != S_IFDIR && type != S_IFLNK)
        return -ENOTDIR;
    if (IS_FINAL(finality) && type != S_IFLNK && strlen(host) < PATH_MAX) {
        b->final_stat = st;
        strcpy(b->final_host, host);
        b->final_valid = true;
    }
    return type == S_IFLNK;
}

static int host_readlink(void *opaque, const char *path, char *out, size_t size)
{
    const Bridge *b = opaque;
    for (int i = 0; b->optimistic && b->hints && i < b->hints->count; i++)
        if (!strcmp(b->hints->path[i], path)) {
            size_t n = strlen(b->hints->target[i]);
            if (n > size) n = size;
            memcpy(out, b->hints->target[i], n);
            return (int)n;
        }
    return (int)raw_syscall(__NR_readlinkat, AT_FDCWD, (long)path, (long)out,
                           size, 0, 0);
}

static int visible_guest_path(Bridge *b, const char *host, char *guest);
static int preferred_guest_path(Bridge *b, const char *host, char *guest);
#ifdef GUARDED
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
#ifdef GUARDED
    guarded = g_payload_config.guard == GUARD_READS;
#endif
    int rc = preferred_guest_path(b, target, b->proc_guest);
    if (rc < 0) return guarded ? -EACCES : 0;
#ifdef GUARDED
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
/* R6: the same path of the merged view in two layers (a directory merges;
 * a lower file a descriptor still holds was copied up since): named the
 * same, it is the same guest name. named is already the upper's form. */
static bool union_same(Bridge *b, const char *named, const char *mapped)
{
    if (!b->union_on) return false;
    const char *rel;
    const struct union_view *u = b->map_view; /* host_map just made mapped */
    if (!u || union_layer_of(u, mapped, &rel) < 0) return false;
    size_t n = u->length[0];
    return !strncmp(named, u->layer[0], n) && !strcmp(named + n, rel);
}

static int visible_guest_path(Bridge *b, const char *host, char *guest)
{
    char *mapped = b->mapped;
    if (glue_guest(host, guest)) return 0;
    /* R6: a lower layer's object, named as the upper names its path. */
    const char *named = host;
    if (b->union_on && bridge_alias(b, host, b->union_named)) named = b->union_named;
    int rc = binding_table_map(&b->table, HOST, named, guest);
    if (rc < 0) return rc;
    rc = host_map(b, guest, mapped);
    if (rc < 0) return rc;
    return strcmp(host, mapped) && !union_same(b, named, mapped) ? -EXDEV : 0;
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
    const char *named = host;
    if (b->union_on && bridge_alias(b, host, b->union_named)) named = b->union_named;
    Comparison prefix_match = compare_paths(host_prefix, named);
    if (prefix_match != PATHS_ARE_EQUAL && prefix_match != PATH1_IS_PREFIX)
        return -EXDEV;
    strcpy(guest, named);
    rc = binding_replace_core(guest, host_prefix, guest_prefix);
    if (rc < 0) return rc;
    rc = binding_table_mount_id(&b->table, guest, &mapped_id);
    if (rc < 0) return rc;
    if (mapped_id != id) return -EXDEV;
    char *mapped = b->mapped;
    rc = host_map(b, guest, mapped);
    if (rc < 0) return rc;
    return strcmp(host, mapped) && !union_same(b, named, mapped) ? -EXDEV : 0;
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
#ifdef GUARDED
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

    char link[64] = "/proc/self/fd/", digits[16], *host = b->fd_host;
    unsigned int value = (unsigned int)fd;
    size_t count = 0, pos = strlen(link);
    do {
        digits[count++] = '0' + value % 10;
        value /= 10;
    } while (value);
    while (count)
        link[pos++] = digits[--count];
    link[pos] = 0;

    int rc = host_readlink(opaque, link, host, PATH_MAX);
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
    long ret = raw_syscall(__NR_getcwd, (long)b->host, sizeof(b->host), 0, 0, 0, 0);
    if (ret < 0)
        return ret;
    if (b->anchor.known && b->anchor_fd == AT_FDCWD)
        return observed_guest_path(b, b->host, b->cwd);
    return visible_guest_path(b, b->host, b->cwd);
}

static int resolve_once(Bridge *b, int dirfd, const char *path, bool follow);

#ifdef GUARDED
#define RACED 1 /* secure_host: a component changed into a non-directory. */
/* Replaces b->host by "/proc/self/fd/N/<last>" where N is the parent
 * directory, opened from the mount's configured host root one component at
 * a time with O_NOFOLLOW: no intermediate component is looked up by name
 * again, so swapping one for a symlink after resolution cannot send the call
 * outside the view (PRoot itself has this race). Only the final component
 * is looked up by the kernel, with the call's own follow semantics. */
/* One O_PATH descriptor per mount root, opened once per process (a full
 * host path walk is the expensive part on this storage), kept at a high
 * number and close-on-exec. The guest may close or reuse that number, so
 * each use checks it still names the same directory, else reopens it. */
static long mount_root_fd[CONFIG_MOUNT_IDS];
static unsigned long mount_root_dev[CONFIG_MOUNT_IDS], mount_root_ino[CONFIG_MOUNT_IDS];
/* An emulated mount's slot is reused by later mounts: its id tags the FD. */
static uint32_t mount_root_tag[CONFIG_MOUNT_IDS];

static long mount_root(Bridge *b, size_t mount, const char *prefix, size_t plen)
{
    if (mount >= CONFIG_MOUNT_IDS) return -EINVAL;
    size_t slot = mount - 1 - (size_t)g_payload_config.bind_count;
    uint32_t tag = mount > (size_t)g_payload_config.bind_count && slot < (size_t)b->mount_count ?
        b->mounts[slot].id : 0;
    long fd = __atomic_load_n(&mount_root_fd[mount], __ATOMIC_ACQUIRE) - 1;
    struct stat st;
    if (fd >= 0 && __atomic_load_n(&mount_root_tag[mount], __ATOMIC_ACQUIRE) == tag &&
        !raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0) &&
        st.st_dev == __atomic_load_n(&mount_root_dev[mount], __ATOMIC_ACQUIRE) &&
        st.st_ino == __atomic_load_n(&mount_root_ino[mount], __ATOMIC_ACQUIRE) &&
        (st.st_mode & S_IFMT) == S_IFDIR)
        return fd;
    memcpy(b->mapped, plen ? prefix : "/", plen ? plen : 1);
    b->mapped[plen ? plen : 1] = 0;
    long opened = raw_syscall(__NR_openat, AT_FDCWD, (long)b->mapped,
                              O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
    if (opened < 0) return opened;
    long high = raw_syscall(__NR_fcntl, opened, F_DUPFD_CLOEXEC, 512, 0, 0, 0);
    if (high >= 0) { raw_syscall(__NR_close, opened, 0, 0, 0, 0, 0); opened = high; }
    if (raw_syscall(__NR_fstat, opened, (long)&st, 0, 0, 0, 0) < 0) return opened;
    /* Publish; a concurrent opener's copy is simply kept by whoever won. */
    __atomic_store_n(&mount_root_tag[mount], tag, __ATOMIC_RELEASE);
    __atomic_store_n(&mount_root_dev[mount], st.st_dev, __ATOMIC_RELEASE);
    __atomic_store_n(&mount_root_ino[mount], st.st_ino, __ATOMIC_RELEASE);
    __atomic_store_n(&mount_root_fd[mount], opened + 1, __ATOMIC_RELEASE);
    return opened;
}

static int secure_host(Bridge *b)
{
    if (!b->secure) return 0;
    if (b->walk_count >= 4) return -ENFILE; /* Never fall back to an unwalked path. */
    size_t mount;
    if (binding_table_mount_id(&b->table, b->guest, &mount) < 0) return 0;
    const char *prefix = mount ? b->table.entries[mount - 1].host : b->table.root;
    size_t plen = strlen(prefix);
    while (plen > 1 && prefix[plen - 1] == '/') plen--;
    /* Kernel magic links (/proc/self, fd links) are meant to be followed. */
    if (!strncmp(prefix, "/proc", 5) && (plen == 5 || prefix[5] == '/')) return 0;
    if (plen == 1) plen = 0; /* Root "/": every component is walked. */
    if (strncmp(b->host, prefix, plen) || (b->host[plen] && b->host[plen] != '/'))
        return 0; /* Not under its mount's host root (the glue tree). */
    const char *rest = b->host + plen;
    size_t end = strlen(rest);
    while (end && rest[end - 1] == '/') end--;
    if (!end) return 0; /* The mount root itself. */
    size_t base = end;
    while (base && rest[base - 1] != '/') base--;
    if (plen >= PATH_MAX) return -ENAMETOOLONG;
    long root = mount_root(b, mount, prefix, plen);
    if (root < 0) return (int)root;
    long dir = root; /* Cached: never closed here. */
    for (size_t at = 0; at < base;) {
        while (at < base && rest[at] == '/') at++;
        size_t next = at;
        while (next < base && rest[next] != '/') next++;
        if (next == at) break;
        memcpy(b->mapped, rest + at, next - at);
        b->mapped[next - at] = 0;
        long child = raw_syscall(__NR_openat, dir, (long)b->mapped,
                                 O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0, 0, 0);
        if (dir != root) raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0);
        if (child < 0) return child == -ELOOP || child == -ENOTDIR ? RACED : (int)child;
        dir = child;
        at = next;
    }
    if (dir == root) {
        /* The parent is the mount root: hold a private copy for the call. */
        dir = raw_syscall(__NR_fcntl, root, F_DUPFD_CLOEXEC, 256, 0, 0, 0);
        if (dir < 0) return (int)dir;
    }
    /* A followed final name is held by inode, so a symlink swapped in now
     * is never followed; the call then names that inode through its magic
     * link. If resolution looked at it, it must be the same file (dev/ino),
     * else it is resolved again; a symlink is always a race; missing stays
     * ENOENT. Deferred opens keep the name and use O_NOFOLLOW instead. */
    bool whole = b->follow_final && !b->defer_final;
    if (whole) {
        memcpy(b->mapped, rest + base, end - base);
        b->mapped[end - base] = 0;
        long node = raw_syscall(__NR_openat, dir, (long)b->mapped, O_PATH | O_NOFOLLOW | O_CLOEXEC,
                                0, 0, 0);
        raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0);
        if (node < 0) return (int)node;
        /* "." and trailing slashes name the directory itself. */
        struct stat now;
        if (raw_syscall(__NR_fstat, node, (long)&now, 0, 0, 0, 0) < 0 ||
            (now.st_mode & S_IFMT) == S_IFLNK ||
            (b->final_valid && (now.st_dev != b->final_stat.st_dev ||
                                now.st_ino != b->final_stat.st_ino))) {
            raw_syscall(__NR_close, node, 0, 0, 0, 0, 0);
            return RACED;
        }
        dir = node;
    }
    /* Held across the guest's call: keep it off the low numbers, which the
     * call itself may need (open after close(1) must get 1). */
    long high = raw_syscall(__NR_fcntl, dir, F_DUPFD_CLOEXEC, 256, 0, 0, 0);
    if (high >= 0) {
        raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0);
        dir = high;
    }
    char name[40] = "/proc/self/fd/";
    size_t n = strlen(name);
    char digits[12];
    int count = 0;
    unsigned long v = (unsigned long)dir;
    do { digits[count++] = '0' + v % 10; v /= 10; } while (v);
    while (count) name[n++] = digits[--count];
    if (whole) {
        name[n] = 0;
        strcpy(b->host, name);
        b->walk_fd[b->walk_count++] = (int)dir;
        return 0;
    }
    name[n++] = '/';
    size_t tail = strlen(rest + base);
    if (n + tail >= PATH_MAX) { raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0); return -ENAMETOOLONG; }
    memmove(b->host + n, rest + base, tail + 1);
    memcpy(b->host, name, n);
    b->walk_fd[b->walk_count++] = (int)dir;
    return 0;
}
#endif

/* A deferred final lookup does not know where a final symlink points, and
 * policy decisions may depend on its target: any failure is resolved again
 * with the full lookup before it is reported. */
/* Without ".." a path resolves lexically exactly when no component is a
 * symlink (a ".." would silently undo a symlink the broker never sees). */
static bool lexical_path(const char *path)
{
    for (const char *p = path; *p;) {
        while (*p == '/') p++;
        if (p[0] == '.' && p[1] == '.' && (!p[2] || p[2] == '/')) return false;
        while (*p && *p != '/') p++;
    }
    return true;
}

/* R6: after a resolution, what the call needs of the merged view: an object
 * it changes is copied up, a name it creates gets its parents in the upper
 * and loses its whiteout. b->host then names the upper's copy. */
static int union_prepare(Bridge *b)
{
    const char *rel = "";
    b->uv = b->final_view;
    int layer = b->uv ? union_layer_of(b->uv, b->host, &rel) : -1;
    if (layer < 0) b->uv = NULL;
    b->union_layer = layer;
    if (layer < 0) return 0;
    if (strlen(rel) >= PATH_MAX) return -ENAMETOOLONG;
    strcpy(b->union_rel, rel);
    long rc = 0;
    switch (b->union_op) {
    case UOP_OPEN: {
        long f = b->open_flags;
        bool tmpfile = (f & O_TMPFILE) == O_TMPFILE;
        bool writes = (f & O_ACCMODE) != O_RDONLY || (f & O_TRUNC) || tmpfile;
        if (layer > 0) {
            /* A layer image's file: its content before the kernel opens it. */
            if (!writes) return (int)union_lazy_fill(b->uv, b->host);
            if ((f & O_CREAT) && (f & O_EXCL)) return -EEXIST;
            rc = union_copy_up(b->uv, b->union_rel, !(f & O_TRUNC) || tmpfile);
            break;
        }
        struct stat st;
        if (!(f & O_CREAT) || tmpfile ||
            !raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st, AT_SYMLINK_NOFOLLOW, 0, 0))
            return 0;
        bool opaque;
        rc = union_prepare_create(b->uv, b->union_rel, &opaque);
        if (rc == -EEXIST) rc = 0;
        break;
    }
    case UOP_COPY:
        if (layer == 0) return 0;
        rc = union_copy_up(b->uv, b->union_rel, true);
        break;
    case UOP_CREATE:
        /* An existing lower name: the kernel's answer for any name. */
        if (layer > 0) return -EEXIST;
        rc = union_prepare_create(b->uv, b->union_rel, &b->union_opaque);
        if (rc == -EEXIST) rc = 0;
        break;
    default:
        return 0;
    }
    if (rc < 0) return (int)rc;
    b->umemo.valid = false;
    if (layer > 0) {
        size_t n = b->uv->length[0];
        if (n + strlen(b->union_rel) >= PATH_MAX) return -ENAMETOOLONG;
        memcpy(b->host, b->uv->layer[0], n);
        strcpy(b->host + n, b->union_rel);
        b->union_layer = 0;
        b->final_valid = false;
    }
    return 0;
}

/* The layer of the object a descriptor names (union_rel set), -1 if none. */
static int union_fd(Bridge *b, int fd)
{
    char link[32] = "/proc/self/fd/", digits[12];
    size_t at = strlen(link);
    int count = 0;
    unsigned v = (unsigned)fd;
    do { digits[count++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (count) link[at++] = digits[--count];
    link[at] = 0;
    int n = host_readlink(b, link, b->fd_host, PATH_MAX - 1);
    if (n < 0) return n == -ENOENT ? -EBADF : n;
    b->fd_host[n] = 0;
    const char *rel;
    int layer = -1;
    b->uv = bridge_view(b, b->fd_host, &layer, &rel);
    if (layer > 0) strcpy(b->union_rel, rel);
    return layer;
}

static int resolve(Bridge *b, int dirfd, const char *path, bool follow)
{
    b->optimistic = b->optimistic_allowed && path && lexical_path(path);
    if (b->optimistic && !b->optimistic_used) {
        b->optimistic_used = true;
        broker_strict(1);
    }
    int rc = resolve_once(b, dirfd, path, follow);
    /* /proc is emulated through lookups (self, fd links): not lexical. */
    Comparison proc = rc >= 0 && b->optimistic ? compare_paths("/proc", b->guest) : PATHS_ARE_NOT_COMPARABLE;
    if (proc == PATHS_ARE_EQUAL || proc == PATH1_IS_PREFIX) {
        /* The whole call again, fully (bridge_run). */
        b->force_full = true;
        return -ELOOP;
    }
    if (rc < 0 && b->defer_final) {
        b->defer_final = false;
        rc = resolve_once(b, dirfd, path, follow);
    }
    b->final_match = rc >= 0 && b->final_valid && !strcmp(b->final_host, b->host);
#ifdef GUARDED
    /* A race seen by the secure walk is resolved once more, then refused. */
    for (int attempt = 0; rc >= 0 && attempt < 2; attempt++) {
        int s = secure_host(b);
        if (s != RACED) return s < 0 ? s : rc;
        if (attempt) return -ELOOP;
        rc = resolve_once(b, dirfd, path, follow);
        b->final_match = rc >= 0 && b->final_valid && !strcmp(b->final_host, b->host);
    }
#endif
    return rc;
}

static int resolve_once(Bridge *b, int dirfd, const char *path, bool follow)
{
    if (!path)
        return -EFAULT;
    b->umemo.valid = false;
    b->union_layer = -1;
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
    ops.respell = respell;
    PathResolver resolver = {{b, &ops, b->path_frames, BRIDGE_FRAMES, deep_frames}, b->cwd,
                             host_fd, host_map, b->resolve_scratch};
    b->follow_final = follow;
    b->final_valid = false;
    b->map_view = NULL;
    int rc = resolve_path_core(&resolver, dirfd, path, follow, b->guest, b->host);
    b->final_view = b->map_view; /* the final mapping is the last */
    if (rc >= 0) {
        int glue = glue_host(b);
        if (glue < 0) return glue;
        /* The tree is shared and read-only, even for its owner or root. A
         * creation over an existing name keeps the kernel's EEXIST. */
        if (glue && b->mutation) {
            struct stat st;
            if (b->attributes) return -EPERM;
            if (!b->creates || raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st,
                                           AT_SYMLINK_NOFOLLOW, 0, 0) < 0)
                return -EACCES;
        }
    }
#ifdef GUARDED
    if (rc >= 0 && b->reads) {
        /* ".." skips lookup, so the final name is classified again. */
        int visibility = path_visibility(b, b->guest);
        if (visibility < 0) return visibility;
        if (visibility == FS_HIDDEN || (visibility == FS_TRAVERSE && !b->traverse))
            return -EACCES;
    }
    /* (The emulated loop devices are no file of the mount they appear in.) */
    if (rc >= 0 && b->mutation && g_payload_config.guard >= GUARD_PATHS &&
        !(mounts_enabled() && loop_device(b->guest) != -1)) {
        size_t mount;
        rc = binding_table_mount_id(&b->table, b->guest, &mount);
        if (rc < 0) return rc;
        /* Do not turn inferred reverse mappings of imported FDs/cwd into grants. */
        rc = fd_runtime_check_path_mutation(mount, path[0] == '/' || b->anchor.known);
        /* The kernel looks the name up before checking a read-only mount:
         * creating an existing name is EEXIST (mkdir -p walks from "/"). */
        struct stat st;
        if (rc == -EROFS && b->creates &&
            !raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st,
                         AT_SYMLINK_NOFOLLOW, 0, 0))
            rc = -EEXIST;
    }
#endif
    /* Last: a refused change must not copy anything up. */
    if (rc >= 0 && b->union_on) {
        int u = union_prepare(b);
        if (u < 0) return u;
    }
    return rc;
}

int proot_handles_syscall(long number)
{
    switch (number) {
    case __NR_mount:
    case __NR_umount2:
        return mounts_enabled();
    case __NR_setxattr: case __NR_lsetxattr:
    case __NR_getxattr: case __NR_lgetxattr:
    case __NR_listxattr: case __NR_llistxattr:
    case __NR_removexattr: case __NR_lremovexattr:
    case __NR_inotify_add_watch:
    case __NR_bind: case __NR_connect: case __NR_sendto: case __NR_sendmsg:
    case __NR_fchmodat:
    case __NR_fchownat:
    case __NR_utimensat:
    case __NR_fchmod:
    case __NR_fchown:
    case __NR_statfs:
    case __NR_fstatfs:
    case __NR_mknodat:
    case __NR_truncate:
    case __NR_ftruncate:
    case __NR_mkdirat:
    case __NR_unlinkat:
    case __NR_symlinkat:
    case __NR_linkat:
    case __NR_renameat:
    case __NR_renameat2:
    case __NR_openat:
    case __NR_newfstatat:
    case __NR_statx:
    case __NR_readlinkat:
    case __NR_chdir:
    case __NR_fchdir:
    case __NR_getcwd:
    case __NR_faccessat:
    case __NR_faccessat2:
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

/* --link-copy (opt-in, like PRoot's -l): some storage refuses every hard
 * link (HarmonyOS shared storage and Android FUSE with EPERM, HarmonyOS app
 * storage with EACCES), which breaks dpkg's backups. The new name becomes a
 * copy of a regular file or symlink: same content, mode and times, but NOT
 * the same inode, so later changes to one name do not reach the other. A
 * copy needs the same directory write permission, so a genuine permission
 * error still fails; so does any failed step, leaving no partial copy.
 * Anything else keeps the error. */
static long copy_link(Bridge *b, long error)
{
    struct stat st;
    if (raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->first_host, (long)&st,
                    AT_SYMLINK_NOFOLLOW, 0, 0) < 0)
        return error;
    if ((st.st_mode & S_IFMT) == S_IFLNK) {
        long n = raw_syscall(__NR_readlinkat, AT_FDCWD, (long)b->first_host,
                             (long)b->proc_data, sizeof(b->proc_data) - 1, 0, 0);
        if (n < 0 || n >= (long)sizeof(b->proc_data) - 1) return error;
        b->proc_data[n] = 0;
        return raw_syscall(__NR_symlinkat, (long)b->proc_data, AT_FDCWD, (long)b->host, 0, 0, 0) < 0 ?
            error : 0;
    }
    if ((st.st_mode & S_IFMT) != S_IFREG) return error;
    long in = raw_syscall(__NR_openat, AT_FDCWD, (long)b->first_host, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (in < 0) return error;
    long out = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host,
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, st.st_mode & 07777, 0, 0);
    long ret = out < 0 ? out : 0;
    while (!ret) {
        long n = raw_syscall(__NR_read, in, (long)b->proc_data, sizeof(b->proc_data), 0, 0, 0);
        if (n <= 0) { ret = n < 0 ? n : 1; break; }
        for (long done = 0; done < n && !ret;) {
            long w = raw_syscall(__NR_write, out, (long)b->proc_data + done, n - done, 0, 0, 0);
            if (w <= 0) ret = w < 0 ? w : -EIO;
            else done += w;
        }
    }
    if (ret == 1) {
        struct { long sec, nsec; } times[2] = {{st.st_atime, st.st_atime_nsec},
                                               {st.st_mtime, st.st_mtime_nsec}};
        ret = raw_syscall(__NR_fchmod, out, st.st_mode & 07777, 0, 0, 0, 0);
        if (!ret) ret = raw_syscall(__NR_utimensat, out, 0, (long)times, 0, 0, 0);
    }
    raw_syscall(__NR_close, in, 0, 0, 0, 0, 0);
    if (out >= 0) raw_syscall(__NR_close, out, 0, 0, 0, 0, 0);
    if (ret < 0 && out >= 0) raw_syscall(__NR_unlinkat, AT_FDCWD, (long)b->host, 0, 0, 0, 0);
    /* A name that already exists stays the kernel's answer. */
    return ret < 0 ? (out == -EEXIST ? -EEXIST : error) : 0;
}

/* ---- R5: owners and modes the host cannot hold (container_state.h) ---- */
static long host_stat(const char *host, bool follow, struct stat *st)
{
    return raw_syscall(__NR_newfstatat, AT_FDCWD, (long)host, (long)st,
                       follow ? 0 : AT_SYMLINK_NOFOLLOW, 0, 0);
}

/* chmod with an owner database: the host keeps owner rw (rwx for a
 * directory); bits the host refuses (setuid, sticky) are dropped there.
 * The guest's mode is recorded when the host's differs. */
static long owners_apply_mode(long fd, const char *host, const struct stat *st, unsigned mode)
{
    long rc = owners_may_chmod(st);
    if (rc < 0) return rc;
    unsigned wanted = owners_host_mode(st, mode);
    static const unsigned drops[] = {0, 06000, 07000};
    for (size_t i = 0; i < 3; i++) {
        unsigned applied = wanted & ~drops[i];
        rc = host ? raw_syscall(__NR_fchmodat, AT_FDCWD, (long)host, applied, 0, 0, 0) :
            raw_syscall(__NR_fchmod, fd, applied, 0, 0, 0, 0);
        if (rc == -EPERM && i < 2) continue;
        if (rc < 0) return rc;
        owners_chmod_done(st, mode, applied);
        return 0;
    }
    return rc;
}

/* After a call that made a new name at b->host. */
static void owners_new_name(Bridge *b)
{
    struct stat st;
    if (owners_enabled() && !host_stat(b->host, false, &st))
        owners_created(&st);
}

/* The object an unlink or a replacing rename takes the last name of. */
static void owners_last_name(const struct stat *st, bool known)
{
    if (known && ((st->st_mode & S_IFMT) == S_IFDIR || st->st_nlink <= 1))
        owners_forget(st);
}

static long mutate(Bridge *b, long number, long a[6])
{
    long ret;
    if (number == __NR_symlinkat) {
        if (!a[0])
            return -EFAULT;
        /* The target is opaque link data, NOT a path to resolve or rewrite. */
        ret = resolve(b, (int)a[1], (const char *)a[2], false);
        if (ret < 0)
            return ret;
        ret = raw_syscall(number, a[0], AT_FDCWD, (long)b->host, 0, 0, 0);
        if (!ret) owners_new_name(b);
        return ret;
    }
    if (number == __NR_mkdirat || number == __NR_unlinkat) {
        ret = resolve(b, (int)a[0], (const char *)a[1], false);
        if (ret < 0)
            return ret;
        if (number == __NR_unlinkat && contains_mount(b, b->guest))
            return -EBUSY;
        if (number == __NR_unlinkat && b->union_layer >= 0)
            return union_remove(b->uv, b->union_rel, a[2] & AT_REMOVEDIR);
        struct stat old;
        bool known = number == __NR_unlinkat && owners_enabled() && !host_stat(b->host, false, &old);
        ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2], 0, 0, 0);
        if (!ret && number == __NR_mkdirat && b->union_layer >= 0 && b->union_opaque)
            union_make_opaque(b->uv, b->union_rel);
        if (!ret && number == __NR_mkdirat) owners_new_name(b);
        if (!ret) owners_last_name(&old, known);
        return ret;
    }

    bool hardlink = number == __NR_linkat;
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
    b->first_union_layer = b->union_layer;
    b->first_uv = b->uv;
    if (b->union_layer >= 0) strcpy(b->first_union_rel, b->union_rel);
    size_t first_mount, second_mount;
    ret = binding_table_mount_id(&b->table, b->first_guest, &first_mount);
    if (ret < 0)
        return ret;
    /* The new name of a link is made in the upper. */
    if (hardlink && b->union_on) b->union_op = UOP_CREATE;
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
    if (!hardlink && b->first_union_layer >= 0 && b->union_layer >= 0 && b->first_uv != b->uv)
        return -EXDEV;
    if (!hardlink && b->first_union_layer >= 0 && b->union_layer >= 0)
        return union_rename(b->uv, b->first_union_rel, b->union_rel,
                            number == __NR_renameat2 ? (unsigned)a[4] : 0);
    if (!hardlink && (b->first_union_layer >= 0) != (b->union_layer >= 0))
        return -EXDEV;
    /* A rename that replaces a name may take its object's last one. */
    struct stat old, moved;
    bool known = !hardlink && owners_enabled() && !(a[4] & 2 /* RENAME_EXCHANGE */) &&
        !host_stat(b->host, false, &old) && !host_stat(b->first_host, false, &moved) &&
        (old.st_dev != moved.st_dev || old.st_ino != moved.st_ino);
    ret = raw_syscall(number, AT_FDCWD, (long)b->first_host,
                      AT_FDCWD, (long)b->host, a[4], 0);
    if (hardlink && g_payload_config.link_copy && (ret == -EPERM || ret == -EACCES)) {
        ret = copy_link(b, ret);
        if (!ret) owners_new_name(b);
    }
    if (!ret) owners_last_name(&old, known);
    return ret;
}

static bool path_mutation(long number, long a[6])
{
    switch (number) {
    case __NR_faccessat: case __NR_faccessat2:
        return !!((unsigned int)a[2] & 2); /* W_OK queries mutation permission. */
    case __NR_openat:
        /* O_PATH ignores ordinary access/create/truncate flags. */
        if (a[2] & O_PATH) return false;
        return (a[2] & (O_ACCMODE | O_CREAT | O_TRUNC)) ||
               ((a[2] & O_TMPFILE) == O_TMPFILE);
    case __NR_setxattr: case __NR_lsetxattr:
    case __NR_removexattr: case __NR_lremovexattr:
    case __NR_mknodat: case __NR_mkdirat: case __NR_unlinkat: case __NR_symlinkat:
    case __NR_linkat: case __NR_renameat: case __NR_renameat2:
    case __NR_fchmodat: case __NR_fchownat: case __NR_utimensat: case __NR_truncate:
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
    case __NR_newfstatat: case __NR_statx: case __NR_statfs: case __NR_chdir:
        return true;
    case __NR_faccessat: case __NR_faccessat2:
        return !((unsigned int)a[2] & 2);
    case __NR_openat:
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
    /* Container networks: an IPv4/IPv6 address moves onto the container's
     * own loopback address (net_view.h). */
    uint16_t family = 0;
    if (name && length >= 2) memcpy(&family, name, 2);
    if (net_enabled() && (family == AF_INET || family == AF_INET6)) {
        unsigned char moved[128];
        unsigned moved_length;
        long rc = net_address(number, a[0], name, (unsigned)length, moved, &moved_length);
        if (rc < 0) return rc;
        if (message) {
            b->message.name = moved;
            b->message.name_length = (int)moved_length;
            return raw_syscall(number, a[0], (long)&b->message, a[2], 0, 0, 0);
        }
        if (sending) return raw_syscall(number, a[0], a[1], a[2], a[3], (long)moved, moved_length);
        return raw_syscall(number, a[0], (long)moved, moved_length, 0, 0, 0);
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
    /* Isolation mode: the broker binds or connects the socket to the host
     * path (any length); the guest has no datagram socket to name. */
    if (g_payload_config.isolate) {
        if (sending || message) return -EPERM;
        return raw_syscall(number == __NR_bind ? BROKER_BIND_PATH : BROKER_CONNECT_PATH,
                           a[0], (long)b->host, 0, 0, 0, 0);
    }
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
        directory = raw_syscall(__NR_openat, AT_FDCWD, (long)(slash == 1 ? "/" : b->host),
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
static int loop_device(const char *guest)
{
    if (strncmp(guest, "/dev/loop", 9)) return -1;
    const char *p = guest + 9;
    if (!strcmp(p, "-control")) return LOOP_CONTROL;
    if (p[0] >= '0' && p[0] < '0' + MOUNT_LOOPS && !p[1]) return p[0] - '0';
    return -1;
}

/* The device a FD of loop_open is, as loop_device; -1 for another FD. */
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
static long loop_path_call(long number, long a[6], int device)
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
    long ret = resolve(b, AT_FDCWD, source, true);
    if (ret < 0) return 0;
    int device = loop_device(b->guest);
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
    int device = loop_device(source);
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
            long ret = resolve(b, AT_FDCWD, value, true);
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

static long mount_call(Bridge *b, long a[6])
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
    long ret = resolve(b, AT_FDCWD, target, true);
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
        ret = resolve(b, AT_FDCWD, source, true);
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
        ret = resolve(b, AT_FDCWD, source, true);
        if (ret < 0) return ret;
        struct stat st;
        ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st, 0, 0, 0);
        if (ret < 0) return ret;
        memset(e, 0, sizeof(*e)); /* resolution may use the same scratch */
        if (((st.st_mode & S_IFMT) == S_IFDIR) != ((target_st.st_mode & S_IFMT) == S_IFDIR))
            return -ENOTDIR;
        /* R6: a bind of the merged view is merged too (named by the upper). */
        if (b->union_on && bridge_alias(b, b->host, b->union_named)) strcpy(b->host, b->union_named);
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

static long umount_call(Bridge *b, long a[6])
{
    const char *target = (const char *)a[0];
    long flags = (int)a[1];
    if (flags & ~(1 | 2 | 4 | 8)) /* MNT_FORCE, MNT_DETACH, MNT_EXPIRE, UMOUNT_NOFOLLOW */
        return -EINVAL;
    if (!guest_string(target, PATH_MAX))
        return -EFAULT;
    b->optimistic_allowed = false;
    long ret = resolve(b, AT_FDCWD, target, !(flags & 8));
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

/* /proc/<pid>/mounts, mountinfo (and the task/<tid> ones) of a process of
 * this view: generated from the table. -ENOENT: the kernel's file. */
static long proc_mounts(Bridge *b, int flags)
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

/* /proc/filesystems with emulated mounts: the types mount(2) takes here
 * (HongMeng has no such file; mount -o loop without -t reads it). */
static long proc_filesystems(Bridge *b, int flags)
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

static long dispatch(Bridge *b, long number, long a[6], struct proot_open_origin *origin)
{
    if(number==__NR_faccessat || number==__NR_faccessat2) {
        /* Match the kernel's int ABI before classifying W_OK. */
        a[2]=(int)a[2];
        if((unsigned int)a[2]&~7u)return -EINVAL;
        if(number==__NR_faccessat2) {
            a[3]=(int)a[3];
            if((unsigned int)a[3]&~(AT_EACCESS|AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH))
                return -EINVAL;
        }
    }
    b->mutation = path_mutation(number, a);
    b->attributes = number == __NR_fchmodat || number == __NR_fchownat ||
        number == __NR_utimensat || number == __NR_truncate || number == __NR_setxattr ||
        number == __NR_lsetxattr || number == __NR_removexattr || number == __NR_lremovexattr;
    b->creates = number == __NR_mkdirat || number == __NR_mknodat || number == __NR_symlinkat ||
        number == __NR_bind;
    b->traverse = path_traversal(number, a);
    b->union_op = UOP_READ;
    b->union_opaque = false;
    if (b->union_on) switch (number) {
    case __NR_setxattr: case __NR_lsetxattr: case __NR_removexattr: case __NR_lremovexattr:
    case __NR_truncate: case __NR_utimensat: case __NR_linkat:
        b->union_op = UOP_COPY; break;
    /* With an owner database chown and chmod of a lower object are only
     * recorded: the shared layer's file is not touched. */
    case __NR_fchownat: case __NR_fchmodat:
        b->union_op = owners_enabled() ? UOP_RECORD : UOP_COPY; break;
    case __NR_mkdirat: case __NR_mknodat: case __NR_symlinkat: case __NR_bind:
        b->union_op = UOP_CREATE; break;
    case __NR_openat:
        if (!(a[2] & O_PATH)) { b->union_op = UOP_OPEN; b->open_flags = a[2]; }
        break;
    }
    if (number == __NR_mount)
        return mount_call(b, a);
    if (number == __NR_umount2)
        return umount_call(b, a);
    if (number == __NR_bind || number == __NR_connect ||
        number == __NR_sendto || number == __NR_sendmsg)
        return socket_address(b, number, a);
#ifdef GUARDED
    /* Socket names keep their spelling (bind records it); exec resolves
     * through proot_resolve_exec_path. Everything dispatched here is safe
     * to issue through the walked parent directory. */
    /* In isolation mode the broker walks every path itself. */
    b->secure = g_payload_config.guard >= GUARD_PATHS && !g_payload_config.isolate;
#endif
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
#ifdef GUARDED
        ret = watch_hides_child(b, b->guest);
        if (ret < 0) return ret;
#endif
        return raw_syscall(number, a[0], (long)b->host, a[2], 0, 0, 0);
    }
    /* R6: a descriptor of a lower object: chmod is recorded with an owner
     * database; otherwise it, and utimensat(fd, NULL), copy up first and
     * change the upper's copy (the descriptor keeps reading the lower). */
    if (b->union_on && (number == __NR_fchmod || (number == __NR_utimensat && !a[1]))) {
        ret = union_fd(b, (int)a[0]);
        if (ret < 0) return ret;
        if (ret > 0 && number == __NR_fchmod && owners_enabled()) {
            struct stat st;
            ret = raw_syscall(__NR_fstat, a[0], (long)&st, 0, 0, 0, 0);
            if (ret < 0) return ret;
            ret = owners_may_chmod(&st);
            if (ret < 0) return ret;
            owners_chmod_done(&st, (unsigned)a[1], st.st_mode & 07777);
            return 0;
        }
        if (ret > 0) {
            ret = union_copy_up(b->uv, b->union_rel, true);
            if (ret < 0) return ret;
            size_t n = b->uv->length[0];
            if (n + strlen(b->union_rel) >= PATH_MAX) return -ENAMETOOLONG;
            memcpy(b->host, b->uv->layer[0], n);
            strcpy(b->host + n, b->union_rel);
            if (number == __NR_fchmod)
                return raw_syscall(__NR_fchmodat, AT_FDCWD, (long)b->host, a[1], 0, 0, 0);
            return raw_syscall(__NR_utimensat, AT_FDCWD, (long)b->host, a[2], AT_SYMLINK_NOFOLLOW, 0, 0);
        }
    }
    /* Descriptor operations retain kernel identity; FD policy is a later layer. */
    if ((number == __NR_fchown || number == __NR_fchmod) && owners_enabled()) {
        struct stat st;
        ret = raw_syscall(__NR_fstat, a[0], (long)&st, 0, 0, 0, 0);
        if (ret < 0) return ret;
        return number == __NR_fchown ? owners_chown(&st, (int)a[1], (int)a[2]) :
            owners_apply_mode(a[0], NULL, &st, (unsigned)a[1]);
    }
    if (number == __NR_fchown)
        return fake_chown(raw_syscall(number, a[0], a[1], a[2], 0, 0, 0));
    if (number == __NR_fchmod || number == __NR_fstatfs || number == __NR_ftruncate)
        return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (number == __NR_statfs || number == __NR_truncate) {
        if (!a[0]) return -EFAULT;
        ret = resolve(b, AT_FDCWD, (const char *)a[0], true);
        if (ret < 0) return ret;
        return raw_syscall(number, (long)b->host, a[1], a[2], a[3], a[4], a[5]);
    }
    if (number == __NR_fchownat || number == __NR_utimensat) {
        long flags = a[number == __NR_fchownat ? 4 : 3];
        long allowed = AT_SYMLINK_NOFOLLOW;
        if (number == __NR_fchownat) allowed |= AT_EMPTY_PATH;
        if (flags & ~allowed) return -EINVAL;
        /* Linux utimensat(fd, NULL, ...) is an FD operation. */
        if (number == __NR_utimensat && !a[1])
            return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (!a[1]) return -EFAULT;
        const char *path = (const char *)a[1];
        if (number == __NR_fchownat && owners_enabled()) {
            struct stat st;
            if (!*path && (flags & AT_EMPTY_PATH)) {
                ret = a[0] == AT_FDCWD ? host_stat(".", true, &st) :
                    raw_syscall(__NR_fstat, a[0], (long)&st, 0, 0, 0, 0);
            } else {
                ret = resolve(b, (int)a[0], path, !(flags & AT_SYMLINK_NOFOLLOW));
                if (ret < 0) return ret;
                ret = host_stat(b->host, !(flags & AT_SYMLINK_NOFOLLOW), &st);
            }
            return ret < 0 ? ret : owners_chown(&st, (int)a[2], (int)a[3]);
        }
        if (!*path && number == __NR_fchownat && (flags & AT_EMPTY_PATH))
            ret = raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        else {
            ret = resolve(b, (int)a[0], path, !(flags & AT_SYMLINK_NOFOLLOW));
            if (ret < 0) return ret;
            ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2], a[3], a[4], a[5]);
        }
        return number == __NR_fchownat ? fake_chown(ret) : ret;
    }
    if (number == __NR_mkdirat || number == __NR_unlinkat || number == __NR_symlinkat ||
        number == __NR_linkat || number == __NR_renameat || number == __NR_renameat2)
        return mutate(b, number, a);
    if (number == __NR_fchmodat && owners_enabled()) {
        if (!a[1]) return -EFAULT;
        ret = resolve(b, (int)a[0], (const char *)a[1], true);
        if (ret < 0) return ret;
        struct stat st;
        ret = host_stat(b->host, true, &st);
        if (ret < 0) return ret;
        if (b->union_layer > 0) {
            ret = owners_may_chmod(&st);
            if (ret < 0) return ret;
            owners_chmod_done(&st, (unsigned)a[2], st.st_mode & 07777);
            return 0;
        }
        return owners_apply_mode(-1, b->host, &st, (unsigned)a[2]);
    }
    if (number == __NR_getcwd) {
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
    if (number == __NR_fchdir) {
        ret = host_fd(b, (int)a[0], b->guest);
        if (ret < 0)
            return ret;
#ifdef GUARDED
        ret = path_visibility(b, b->guest);
        if (ret < 0) return ret;
        if (ret == FS_HIDDEN) return -EACCES;
#endif
        ret = raw_syscall(__NR_fchdir, a[0], 0, 0, 0, 0, 0);
        if (ret >= 0 && origin) *origin = b->anchor;
        return ret;
    }
    if (number == __NR_chdir) {
        ret = resolve(b, AT_FDCWD, (const char *)a[0], true);
        if (ret < 0)
            return ret;
        bool known = origin && (((const char *)a[0])[0] == '/' || b->anchor.known);
        size_t id = 0;
        if (known) {
            ret = binding_table_mount_id(&b->table, b->guest, &id);
            if (ret < 0) return ret;
        }
        ret = raw_syscall(__NR_chdir, (long)b->host, 0, 0, 0, 0, 0);
        if (ret >= 0 && known) *origin = (struct proot_open_origin){id, true};
        return ret;
    }

    const char *path = (const char *)a[1];
    if (!path)
        return -EFAULT;
    bool follow = true;
    if (number == __NR_mknodat) {
        follow = false;
    } else if (number == __NR_openat) {
        int flags = (int)a[2];
        follow = !(flags & O_NOFOLLOW) && !((flags & O_CREAT) && (flags & O_EXCL));
    } else if (number == __NR_readlinkat) {
        follow = false;
        if (a[3] <= 0)
            return -EINVAL;
    } else if (number == __NR_newfstatat || number == __NR_faccessat2 || number == __NR_statx) {
        long flags = number == __NR_statx ? a[2] : a[3];
        follow = !(flags & AT_SYMLINK_NOFOLLOW);
        /* No pathname traversal for AT_EMPTY_PATH; preserve the FD operation
         * and let the kernel validate flags/FD/output, including AT_FDCWD. */
        if (!path[0] && (flags & AT_EMPTY_PATH)) {
            if (number == __NR_newfstatat) {
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
            if (number == __NR_statx) {
                /* Empty-path statx likewise refers to the FD itself. */
                return raw_syscall(number, a[0], a[1], flags | AT_SYMLINK_NOFOLLOW,
                                   a[3], a[4], a[5]);
            }
            return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        }
    }
    /* readlinkat supports an empty pathname on an O_PATH symlink FD. */
    if (number == __NR_readlinkat && !path[0])
        return raw_syscall(number, a[0], a[1], a[2], a[3], 0, 0);

    bool observed_open = number == __NR_openat && origin &&
        (path[0] == '/' || b->anchor.known);
    /* A followed open (not O_PATH, which would open the link itself) skips
     * the final lstat and opens with O_NOFOLLOW; only ELOOP, a final
     * symlink, needs the full resolution again. Saves one host walk. */
    size_t length = strnlen(path, PATH_MAX);
    b->defer_final = number == __NR_openat && follow && !(a[2] & O_PATH) &&
        length && length < PATH_MAX && path[length - 1] != '/';
    bool deferred = b->defer_final;
    /* R6: the emulated loop devices, spelled as such (no resolution: the
     * name has no host file, which a guarded final lookup refuses). */
    if (mounts_enabled() && path[0] == '/' && loop_device(path) != -1) {
        b->defer_final = false;
        return loop_path_call(number, a, loop_device(path));
    }
    ret = resolve(b, (int)a[0], path, follow);
    b->defer_final = false;
    if (ret < 0)
        return ret;
    /* R6: the emulated loop devices. */
    if (mounts_enabled()) {
        int device = loop_device(b->guest);
        if (device != -1) return loop_path_call(number, a, device);
    }
    if (number == __NR_readlinkat) {
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
    if ((number == __NR_newfstatat || number == __NR_statx || number == __NR_faccessat ||
         number == __NR_faccessat2) && glue_ancestor(b, b->guest)) {
        struct stat probe;
        if (raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&probe,
                        AT_SYMLINK_NOFOLLOW, 0, 0) == -ENOENT)
            strcpy(b->host, b->table.root);
    }
    /* R5: an O_CREAT open that makes the file records its owner. */
    bool fresh = false;
    if (number == __NR_openat && owners_enabled() && ((a[2] & O_CREAT) || (a[2] & O_TMPFILE) == O_TMPFILE)) {
        struct stat probe;
        fresh = (a[2] & O_EXCL) || (a[2] & O_TMPFILE) == O_TMPFILE || host_stat(b->host, true, &probe) == -ENOENT;
    }
    if (number == __NR_openat && !(a[2] & (O_ACCMODE | O_PATH | O_CREAT))) {
        ret = proc_cmdline(b, (int)a[2]);
        if (ret == -ENOENT && mounts_enabled())
            ret = proc_mounts(b, (int)a[2]);
        if (ret == -ENOENT && mounts_enabled())
            ret = proc_filesystems(b, (int)a[2]);
    } else ret = -ENOENT;
    if (ret == -ENOENT && number == __NR_newfstatat && follow && b->final_match) {
        /* Copied by the kernel so a bad buffer is still EFAULT. */
        struct { const void *base; size_t length; } local = {&b->final_stat, sizeof(b->final_stat)},
            remote = {(void *)a[2], sizeof(b->final_stat)};
        long pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        long n = raw_syscall(__NR_process_vm_writev, pid, (long)&local, 1, (long)&remote, 1, 0);
        if (n == (long)sizeof(b->final_stat)) return 0;
        if (n == -EFAULT) return n;
    }
    if (ret == -ENOENT && deferred) {
        ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2] | O_NOFOLLOW, a[3], 0, 0);
        if (ret != -ELOOP) goto opened;
        /* A final symlink: resolve it in guest terms after all. */
        ret = resolve(b, (int)a[0], path, follow);
        if (ret < 0) return ret;
        if (observed_open) {
            ret = binding_table_mount_id(&b->table, b->guest, &mount_id);
            if (ret < 0) return ret;
        }
        ret = -ENOENT;
    }
    if (ret == -ENOENT)
        ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2], a[3], a[4], a[5]);
 opened:
    if (ret >= 0 && observed_open)
        *origin = (struct proot_open_origin){mount_id, true};
    if (ret >= 0 && fresh) {
        struct stat st;
        if (!raw_syscall(__NR_fstat, ret, (long)&st, 0, 0, 0, 0))
            owners_created(&st);
    }
    if (!ret && number == __NR_mknodat)
        owners_new_name(b);
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
#ifdef GUARDED
    if (!fd_runtime_shared_scratch()) return proot_scratch_alloc(sizeof(Bridge));
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
    for (int i = 0; i < b->walk_count; i++)
        raw_syscall(__NR_close, b->walk_fd[i], 0, 0, 0, 0, 0);
    b->walk_count = 0;
    for (int i = 0; i < BRIDGE_POOL; i++)
        if (__atomic_load_n(&bridge_pool[i], __ATOMIC_ACQUIRE) == b) {
            __atomic_store_n(&bridge_used[i], 0, __ATOMIC_RELEASE);
            return;
        }
    if (b->deep_frames)
        raw_syscall(__NR_munmap, (long)b->deep_frames, DEEP_FRAMES_SIZE, 0, 0, 0, 0);
    proot_scratch_free(b, sizeof(Bridge));
}

static long bridge_create(Bridge **out)
{
    payload_config_t *cfg = &g_payload_config;
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
    b->final_match = false;
    b->secure = false;
    b->walk_count = 0;
    b->defer_final = false;
    b->final_valid = false;
    b->traverse = false;
    b->optimistic_allowed = b->optimistic = b->optimistic_used = b->force_full = false;
    b->hints = NULL;
    b->view_count = 0;
    b->union_on = false;
    b->uv = b->first_uv = NULL;
    b->union_op = UOP_READ;
    b->union_layer = b->first_union_layer = -1;
    b->umemo.valid = false;
    b->anchor_fd = AT_FDCWD;
    b->anchor = (struct proot_open_origin){0, false};
    size_t count = (size_t)cfg->bind_count;
    b->mount_count = mounts_enabled() ? mounts_snapshot(b->mounts, CONFIG_MAX_MOUNTS) : 0;
    for (int i = 0; i < cfg->bind_count; i++)
        b->bindings[i] = b->mount_count && mounts_bind_hidden(b->mounts, b->mount_count, cfg->binds[i].src) ?
            (PathBinding){UNMOUNTED, UNMOUNTED} : (PathBinding){cfg->binds[i].src, cfg->binds[i].dst};
    /* R4: slot i is mount id bind_count + 1 + i; a free or hidden slot
     * keeps its id but matches nothing. */
    for (int i = 0; i < b->mount_count; i++)
        b->bindings[count++] = mounts_hidden(b->mounts, b->mount_count, i) ?
            (PathBinding){UNMOUNTED, UNMOUNTED} : (PathBinding){b->mounts[i].guest, b->mounts[i].host};
    b->table = (BindingTable){cfg->root[0] ? cfg->root : "/", b->bindings, count};
    /* R6: the root's merged view and those of overlay mounts. */
    if (union_enabled())
        b->view_count = union_views(b->views, 1 + MOUNT_OVERLAYS, b->overlay_lowers, b->mounts, b->mount_count);
    b->union_on = b->view_count > 0;
    b->root_union = b->union_on && cfg->lower_count > 0 && cfg->root[0];
    b->map_view = b->final_view = NULL;
    long ret = binding_table_validate(&b->table);
#ifdef GUARDED
    b->reads = false;
    if (ret >= 0 && cfg->guard == GUARD_READS) {
        size_t count;
        ret = fd_runtime_mount_access(b->access, &count);
        b->policy = (struct fs_policy){b->access, count};
        b->exposed_count = 0;
        for (size_t i = 0; ret >= 0 && i < b->table.count; i++) {
            size_t id;
            ret = binding_table_mount_id(&b->table, b->bindings[i].guest, &id);
            /* Shadowed duplicate destinations expose nothing. */
            if (ret >= 0 && id == i + 1 && b->access[id] != FS_DENY && b->bindings[i].guest != UNMOUNTED)
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
#ifdef GUARDED
        int visibility=path_visibility(b,b->guest);
        if(visibility<0)return visibility;
        if(visibility==FS_HIDDEN)return -EXDEV;
#endif
        *selected=0;return 0;
    }
    for(size_t id=0;id<=b->table.count;id++) {
        b->anchor=(struct proot_open_origin){id,true};
        if(observed_guest_path(b,host,b->guest))continue;
#ifdef GUARDED
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
#ifdef GUARDED
        if (rc < 0 && g_payload_config.guard == GUARD_READS) {
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
    ret=raw_syscall(__NR_getcwd,(long)b->first_host,sizeof(b->first_host),0,0,0,0);
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

#ifdef GUARDED
/* Kernel getdents64 record: ino, next offset, reclen, type, NUL-terminated name. */
#define DIRENT_OFFSET 8
#define DIRENT_RECLEN 16
#define DIRENT_NAME 19
/* Isolation mode: naming a directory FD is a round trip to the broker, and
 * a listing takes several getdents calls. The guest name found for an open
 * directory is kept per FD while the FD still refers to the same directory
 * (dev/ino): it only selects names to hide here (the broker decides every
 * access), so a rename of the open directory leaves it merely stale. */
#define DIR_NAMES 4
static struct dir_name {
    long pid;
    int fd;
    unsigned long dev, ino;
    char guest[PATH_MAX];
} dir_names[DIR_NAMES];
static int dir_names_lock, dir_names_next;

static void dir_names_take(void)
{
    while (__atomic_exchange_n(&dir_names_lock, 1, __ATOMIC_ACQUIRE))
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
}
static void dir_names_drop(void) { __atomic_store_n(&dir_names_lock, 0, __ATOMIC_RELEASE); }

static int cached_dir_name(int fd, char *guest, struct stat *st, bool store)
{
    long pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    int found = 0;
    dir_names_take();
    for (int i = 0; i < DIR_NAMES && !store; i++) {
        struct dir_name *d = &dir_names[i];
        if (d->pid == pid && d->fd == fd && d->dev == st->st_dev && d->ino == st->st_ino) {
            strcpy(guest, d->guest);
            found = 1;
            break;
        }
    }
    if (store) {
        struct dir_name *d = &dir_names[dir_names_next++ % DIR_NAMES];
        *d = (struct dir_name){pid, fd, st->st_dev, st->st_ino, ""};
        strcpy(d->guest, guest);
    }
    dir_names_drop();
    return found;
}

long proot_getdents_visible(int fd, void *buffer, unsigned long count,
                            const struct proot_open_origin *anchor)
{
    if (!anchor) return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return ret;
    b->anchor = *anchor;
    b->anchor_fd = fd;
    struct stat dir;
    bool cacheable = g_payload_config.isolate &&
        !raw_syscall(__NR_fstat, fd, (long)&dir, 0, 0, 0, 0) && (dir.st_mode & S_IFMT) == S_IFDIR;
    if (cacheable && cached_dir_name(fd, b->first_guest, &dir, false))
        ret = 0;
    else {
        ret = host_fd(b, fd, b->first_guest);
        if (ret >= 0 && cacheable && strlen(b->first_guest) < PATH_MAX)
            cached_dir_name(fd, b->first_guest, &dir, true);
    }
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

/* A link target spliced in optimistically may only climb ("../" first):
 * those components were walked by the broker; a later ".." would undo an
 * unchecked one. */
static bool climbing_target(const char *target)
{
    const char *p = target;
    while (p[0] == '.' && p[1] == '.' && (p[2] == '/' || !p[2]))
        for (p += 2; *p == '/'; p++)
            ;
    return lexical_path(p);
}

/* Optimistic attempts of one call (isolation mode, see Bridge): each
 * symlink the broker refuses is reported and the call runs again with it
 * known, still optimistic; after LINK_HINTS of them, or a target that is
 * not lexical, with full resolution. A refused attempt has no effect: the
 * broker acts on nothing. */
struct optimism {
    bool on;
    struct link_hints *hints; /* mapped on the first refusal */
};

static void optimism_begin(Bridge *b, struct optimism *o)
{
    b->optimistic_allowed = o->on;
    b->hints = o->hints;
}

/* After an attempt that returned ret: whether to run it again. */
static bool optimism_retry(Bridge *b, struct optimism *o, long ret)
{
    if (!b->optimistic_used)
        return false;
    broker_strict(0);
    if (ret != -ELOOP)
        return false;
    if (!o->hints) {
        long mem = raw_syscall(__NR_mmap, 0, sizeof(*o->hints), 3, 0x22, -1, 0);
        o->hints = (unsigned long)mem >= (unsigned long)-4095 ? NULL : (void *)mem;
        if (o->hints) o->hints->count = 0;
    }
    struct link_hints *h = o->hints;
    o->on = !b->force_full && h && h->count < LINK_HINTS &&
        broker_link_report(h->path[h->count], h->target[h->count]) &&
        climbing_target(h->target[h->count]);
    if (o->on) h->count++;
    return true;
}

static void optimism_end(struct optimism *o)
{
    if (o->hints) raw_syscall(__NR_munmap, (long)o->hints, sizeof(*o->hints), 0, 0, 0, 0);
}

/* One call through the bridge, optimistically first in isolation mode. */
static long bridge_run(long number, long args[6], const struct proot_open_origin *anchor,
                       struct proot_open_origin *origin, const struct proot_path_context *context)
{
    long saved[6];
    memcpy(saved, args, sizeof(saved));
    /* The merged view looks names up itself (and may copy up): never
     * optimistic. */
    struct optimism o = {g_payload_config.isolate && !union_enabled(), NULL};
    for (;;) {
        Bridge *b;
        long ret = bridge_create(&b);
        if (ret < 0) {
            optimism_end(&o);
            return ret;
        }
        b->context = context;
        if (anchor) {
            b->anchor = *anchor;
            b->anchor_fd = (number == __NR_chdir || number == __NR_getcwd) ? AT_FDCWD : (int)args[0];
        }
        optimism_begin(b, &o);
        ret = dispatch(b, number, args, origin);
        bool again = optimism_retry(b, &o, ret);
        bridge_release(b);
        if (!again) {
            optimism_end(&o);
            return ret;
        }
        memcpy(args, saved, sizeof(saved));
    }
}

static long bridge_syscall(long number, long args[6], const struct proot_open_origin *anchor,
                           struct proot_open_origin *origin)
{
    if (!proot_handles_syscall(number))
        return -ENOSYS;
    return bridge_run(number, args, anchor, origin, NULL);
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
    return bridge_syscall(__NR_openat, args, anchor, origin);
}

long proot_cwd(long number, long args[6], const struct proot_open_origin *anchor,
               struct proot_open_origin *origin)
{
    if (!origin || (number != __NR_chdir && number != __NR_fchdir && number != __NR_getcwd))
        return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    return bridge_syscall(number, args, anchor, origin);
}

long proot_context_syscall(long number, long args[6], const struct proot_path_context *context)
{
    if (!context || !proot_handles_syscall(number)) return -EINVAL;
    return bridge_run(number, args, NULL, NULL, context);
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
            /* A layer image's file: its content before it is read. */
            ret = union_lazy_fill(b->final_view, b->host);
        }
    }
    bridge_release(b);
    return (int)ret;
}

/* Isolation mode: resolve an exec path and open it read-only (not
 * close-on-exec) through the broker, optimistically like bridge_run, so a
 * plain path costs one round trip. Returns the FD. */
long proot_open_exec_path(int dirfd, const char *path, bool follow,
                          char *guest, char *host, size_t capacity,
                          const struct proot_path_context *context)
{
    if (!guest || !host || !capacity)
        return -EINVAL;
    struct optimism o = {true, NULL};
    for (;;) {
        Bridge *b;
        long ret = bridge_create(&b);
        if (ret < 0) {
            optimism_end(&o);
            return ret;
        }
        b->context = context;
        optimism_begin(b, &o);
        ret = resolve(b, dirfd, path, follow);
        if (!ret && (strlen(b->guest) >= capacity || strlen(b->host) >= capacity))
            ret = -ENAMETOOLONG;
        if (!ret) {
            strcpy(guest, b->guest);
            strcpy(host, b->host);
            ret = union_lazy_fill(b->final_view, b->host);
            if (!ret)
                ret = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host, O_RDONLY | (follow ? 0 : O_NOFOLLOW),
                                  0, 0, 0);
        }
        bool again = optimism_retry(b, &o, ret);
        bridge_release(b);
        if (!again) {
            optimism_end(&o);
            return ret;
        }
    }
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
        anchor = raw_syscall(__NR_openat, AT_FDCWD, (long)".",
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
    ret = raw_syscall(__NR_openat, anchor, (long)name, flags, 0, 0, 0);
    if (trailing && ret == -ENOTDIR) ret = -EOPNOTSUPP;
    if (ret >= 0 && b->anchor.known)
        *origin = (struct proot_open_origin){target_mount, true};
close_anchor:
    if (dirfd == AT_FDCWD) raw_syscall(__NR_close, anchor, 0, 0, 0, 0, 0);
out:
    bridge_release(b);
    return ret;
}
