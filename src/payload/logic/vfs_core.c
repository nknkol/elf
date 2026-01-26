#include "vfs_core.h"
#include "path_rewrite.h"
#include "syscall_nums.h"
#include "utils.h"
#include "log.h"
#include "mini_libc.h"
#include "execve_utils.h" // For safe_cpy

// Bring in definitions from syscall_hooks that are needed here.
#define AT_FDCWD              (-100)
#define AT_SYMLINK_NOFOLLOW   0x100
#define O_NOFOLLOW            0x20000
#define O_RDONLY              0
#define O_WRONLY              1
#define O_RDWR                2
#define O_CREAT               0x40
#define O_DIRECTORY           0x10000
#define PROT_READ             0x1
#define PROT_WRITE            0x2
#define MAP_PRIVATE           0x02
#define MAP_ANON              0x20
#define SYS_mmap              222
#define SYS_munmap            215

#define ENOENT                2
#define EINVAL                22

#define VFS_MAX_LNODES        512
#define VFS_MAX_DENTS         512
#define VFS_MAX_DIR_CACHE     8
#define VFS_DENT_BUF          4096

extern long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);
extern payload_config_t g_payload_config;

static vfs_state_t g_vfs_state;
static int g_vfs_inited = 0;
static lnode_t g_lnode_pool[VFS_MAX_LNODES];
static int g_lnode_count = 0;

struct vfs_dir_entry {
    char name[CONFIG_MAX_PATH];
    unsigned long ino;
    unsigned char type;
    int from_upper;
    int hidden;
};

struct vfs_dir_cache {
    int fd;
    size_t count;
    size_t pos;
    char virt_path[CONFIG_MAX_PATH];
    struct vfs_dir_entry entries[VFS_MAX_DENTS];
};

static struct vfs_dir_cache g_dir_cache[VFS_MAX_DIR_CACHE];

/*
 * =====================================================================================
 *  Section 1: Symlink Resolution Logic (Moved from syscall_hooks.c)
 * =====================================================================================
 */

struct symlink_chain_scratch {
    char current[CONFIG_MAX_PATH];
    char next[CONFIG_MAX_PATH];
};

static struct symlink_chain_scratch *symlink_chain_scratch_alloc(void)
{
    size_t sz = sizeof(struct symlink_chain_scratch);
    void *p = (void *)raw_syscall(SYS_mmap, 0, (long)sz,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANON, -1, 0);
    if ((long)p < 0)
        return NULL;
    return (struct symlink_chain_scratch *)p;
}

static void symlink_chain_scratch_free(struct symlink_chain_scratch *scratch)
{
    if (!scratch)
        return;
    raw_syscall(SYS_munmap, (long)scratch, (long)sizeof(*scratch), 0, 0, 0, 0);
}

static int resolve_symlink_target_at(long dirfd, const char *path,
                                     char *resolved, size_t resolved_sz)
{
    if (!path || !resolved || resolved_sz == 0)
        return 0;
    char linkbuf[CONFIG_MAX_PATH];
    long n = raw_syscall(SYS_readlinkat, dirfd, (long)path, (long)linkbuf, sizeof(linkbuf) - 1, 0, 0);
    if (n < 0)
        return 0;
    if ((size_t)n >= sizeof(linkbuf))
        n = sizeof(linkbuf) - 1;
    linkbuf[n] = '\0';

    if (linkbuf[0] == '/') {
        rewrite_path(linkbuf, resolved, resolved_sz);
    } else {
        size_t prefix_len = dir_len(path);
        join_paths(resolved, resolved_sz, path, prefix_len, linkbuf);
    }
    return 1;
}

int resolve_symlink_chain_at(long dirfd, const char *path, char *out, size_t out_sz)
{
    if (!path || !out || out_sz == 0)
        return 0;
    struct symlink_chain_scratch *scratch = symlink_chain_scratch_alloc();
    if (!scratch)
        return 0;
    safe_cpy(scratch->current, sizeof(scratch->current), path);

    int changed = 0;
    for (int depth = 0; depth < 4; depth++) {
        if (!resolve_symlink_target_at(dirfd, scratch->current,
                                       scratch->next, sizeof(scratch->next)))
            break;
        safe_cpy(scratch->current, sizeof(scratch->current), scratch->next);
        changed = 1;
    }
    if (!changed) {
        symlink_chain_scratch_free(scratch);
        return 0;
    }
    safe_cpy(out, out_sz, scratch->current);
    symlink_chain_scratch_free(scratch);
    return 1;
}

/*
 * =====================================================================================
 *  Section 2: VFS Core API Implementation
 * =====================================================================================
 */

static int vfs_has_prefix(const char *path, const char *prefix)
{
    if (!path || !prefix)
        return 0;
    if (prefix[0] == '/' && prefix[1] == '\0')
        return path[0] == '/';
    size_t plen = sys_strlen(prefix);
    if (plen == 0)
        return 0;
    for (size_t i = 0; i < plen; i++) {
        if (path[i] != prefix[i])
            return 0;
    }
    char tail = path[plen];
    return tail == '\0' || tail == '/' ? 1 : 0;
}

static void vfs_reset_dir_cache(void)
{
    for (int i = 0; i < VFS_MAX_DIR_CACHE; i++) {
        g_dir_cache[i].fd = -1;
        g_dir_cache[i].count = 0;
        g_dir_cache[i].pos = 0;
        g_dir_cache[i].virt_path[0] = '\0';
    }
}

static void vfs_ensure_init(void)
{
    if (g_vfs_inited)
        return;
    radix_tree_init(&g_vfs_state.tree);
    g_lnode_count = 0;
    vfs_reset_dir_cache();
    safe_cpy(g_vfs_state.lower_root, sizeof(g_vfs_state.lower_root), g_payload_config.vfs_lower);
    safe_cpy(g_vfs_state.upper_root, sizeof(g_vfs_state.upper_root), g_payload_config.vfs_upper);
    if (g_vfs_state.lower_root[0] == '\0' && g_payload_config.root[0]) {
        safe_cpy(g_vfs_state.lower_root, sizeof(g_vfs_state.lower_root), g_payload_config.root);
    }
    g_vfs_state.overlay_count = 0;
    int count = g_payload_config.overlay_count;
    if (count > CONFIG_MAX_OVERLAYS)
        count = CONFIG_MAX_OVERLAYS;
    for (int i = 0; i < count; i++) {
        safe_cpy(g_vfs_state.overlays[i].mount,
                 sizeof(g_vfs_state.overlays[i].mount),
                 g_payload_config.overlays[i].mount);
        safe_cpy(g_vfs_state.overlays[i].lower,
                 sizeof(g_vfs_state.overlays[i].lower),
                 g_payload_config.overlays[i].lower);
        safe_cpy(g_vfs_state.overlays[i].upper,
                 sizeof(g_vfs_state.overlays[i].upper),
                 g_payload_config.overlays[i].upper);
        g_vfs_state.overlay_count++;
    }
    g_vfs_inited = 1;
}

int vfs_core_init(const payload_config_t *config) {
    (void)config;
    vfs_ensure_init();
    return 0;
}

void vfs_core_destroy(void) {
    g_vfs_inited = 0;
}

static lnode_t *vfs_alloc_lnode(void)
{
    if (g_lnode_count >= VFS_MAX_LNODES)
        return NULL;
    lnode_t *node = &g_lnode_pool[g_lnode_count++];
    safe_cpy(node->virt_path, sizeof(node->virt_path), "");
    node->status = LNODE_UNKNOWN;
    node->exists_lower = 0;
    node->exists_upper = 0;
    return node;
}

static lnode_t *vfs_get_lnode(const char *virt_path)
{
    if (!virt_path)
        return NULL;
    lnode_t *node = (lnode_t *)radix_tree_lookup(&g_vfs_state.tree, virt_path);
    if (node)
        return node;
    node = vfs_alloc_lnode();
    if (!node)
        return NULL;
    safe_cpy(node->virt_path, sizeof(node->virt_path), virt_path);
    radix_tree_insert(&g_vfs_state.tree, virt_path, node);
    return node;
}

static const char *vfs_build_layer_path(const char *root, const char *virt_path,
                                        char *out, size_t out_sz)
{
    if (!root || !root[0] || !virt_path || !out || out_sz == 0)
        return NULL;
    if (virt_path[0] != '/') {
        safe_cpy(out, out_sz, virt_path);
        return out;
    }
    join_paths(out, out_sz, root, sys_strlen(root), virt_path);
    return out;
}

static int vfs_build_mount_root(const char *root, const char *mount,
                                char *out, size_t out_sz)
{
    if (!root || !root[0] || !mount || !mount[0] || !out || out_sz == 0)
        return 0;
    if (mount[0] == '/' && mount[1] == '\0') {
        safe_cpy(out, out_sz, root);
        return 1;
    }
    join_paths(out, out_sz, root, sys_strlen(root), mount);
    return 1;
}

static const char *vfs_abspath(const char *virt_path, char *out, size_t out_sz)
{
    if (!virt_path || !out || out_sz == 0)
        return virt_path;
    if (virt_path[0] == '/')
        return virt_path;
    char host_cwd[CONFIG_MAX_PATH];
    long n = raw_syscall(SYS_getcwd, (long)host_cwd, sizeof(host_cwd), 0, 0, 0, 0);
    if (n <= 0)
        return virt_path;
    if ((size_t)n >= sizeof(host_cwd))
        host_cwd[sizeof(host_cwd) - 1] = '\0';
    else
        host_cwd[n] = '\0';
    char virt_cwd[CONFIG_MAX_PATH];
    vfs_reverse_path(host_cwd, virt_cwd, sizeof(virt_cwd));
    join_paths(out, out_sz, virt_cwd, sys_strlen(virt_cwd), virt_path);
    return out;
}

struct vfs_overlay_match {
    const char *mount;
    const char *lower_root;
    const char *upper_root;
};

static int vfs_match_overlay(const char *virt_path, struct vfs_overlay_match *out)
{
    if (!virt_path || !out)
        return 0;
    size_t best_len = 0;
    const char *best_mount = NULL;
    const char *best_lower = NULL;
    const char *best_upper = NULL;

    for (int i = 0; i < g_vfs_state.overlay_count; i++) {
        const char *mount = g_vfs_state.overlays[i].mount;
        if (!mount || !mount[0])
            continue;
        if (!vfs_has_prefix(virt_path, mount))
            continue;
        size_t len = sys_strlen(mount);
        if (len > best_len) {
            best_len = len;
            best_mount = mount;
            best_lower = g_vfs_state.overlays[i].lower;
            best_upper = g_vfs_state.overlays[i].upper;
        }
    }

    if (best_mount) {
        out->mount = best_mount;
        out->lower_root = best_lower;
        out->upper_root = best_upper;
        return 1;
    }

    if (g_vfs_state.overlay_count == 0 &&
        g_vfs_state.lower_root[0] && g_vfs_state.upper_root[0] &&
        virt_path[0] == '/') {
        out->mount = "/";
        out->lower_root = g_vfs_state.lower_root;
        out->upper_root = g_vfs_state.upper_root;
        return 1;
    }

    return 0;
}

static int vfs_host_to_virt(const char *host_path, char *out, size_t out_sz)
{
    if (!host_path || !out || out_sz == 0)
        return 0;
    size_t best_len = 0;
    const char *best_mount = NULL;

    for (int i = 0; i < g_vfs_state.overlay_count; i++) {
        const char *mount = g_vfs_state.overlays[i].mount;
        const char *upper = g_vfs_state.overlays[i].upper;
        const char *lower = g_vfs_state.overlays[i].lower;
        char prefix[CONFIG_MAX_PATH];
        if (upper && upper[0] && vfs_build_mount_root(upper, mount, prefix, sizeof(prefix)) &&
            vfs_has_prefix(host_path, prefix)) {
            size_t len = sys_strlen(prefix);
            if (len > best_len) {
                best_len = len;
                best_mount = mount;
            }
        }
        if (lower && lower[0] && vfs_build_mount_root(lower, mount, prefix, sizeof(prefix)) &&
            vfs_has_prefix(host_path, prefix)) {
            size_t len = sys_strlen(prefix);
            if (len > best_len) {
                best_len = len;
                best_mount = mount;
            }
        }
    }

    if (!best_mount && g_vfs_state.overlay_count == 0 &&
        g_vfs_state.lower_root[0] && g_vfs_state.upper_root[0]) {
        char prefix[CONFIG_MAX_PATH];
        if (vfs_build_mount_root(g_vfs_state.upper_root, "/", prefix, sizeof(prefix)) &&
            vfs_has_prefix(host_path, prefix)) {
            best_mount = "/";
            best_len = sys_strlen(prefix);
        } else if (vfs_build_mount_root(g_vfs_state.lower_root, "/", prefix, sizeof(prefix)) &&
                   vfs_has_prefix(host_path, prefix)) {
            best_mount = "/";
            best_len = sys_strlen(prefix);
        }
    }

    if (!best_mount)
        return 0;

    const char *suffix = host_path + best_len;
    if (*suffix == '\0')
        suffix = "";
    join_paths(out, out_sz, best_mount, sys_strlen(best_mount), suffix);
    return 1;
}

static int vfs_is_write_intent(long sys_no, long *args)
{
    if (sys_no == SYS_openat) {
        int flags = (int)args[2];
        if (flags & (O_WRONLY | O_RDWR | O_CREAT))
            return 1;
    }
    switch (sys_no) {
        case SYS_mkdirat:
        case SYS_mknodat:
        case SYS_unlinkat:
        case SYS_renameat:
        case SYS_symlinkat:
        case SYS_linkat:
        case SYS_fchmodat:
        case SYS_fchownat:
        case SYS_utimensat:
        case SYS_fchmod:
        case SYS_fchown:
            return 1;
        default:
            return 0;
    }
}

static vfs_path_result_t vfs_resolve_rewrite(const char *virt_path, long sys_no, long *args)
{
    vfs_path_result_t result;
    if (!virt_path) {
        result.path = virt_path;
        result.error = 0;
        return result;
    }

    // Path rewrite
    static char rewrite_buf[CONFIG_MAX_PATH];
    static char resolve_buf[CONFIG_MAX_PATH];
    const char *rw_path = rewrite_path(virt_path, rewrite_buf, sizeof(rewrite_buf));

    // Symlink resolution logic, moved from syscall_hooks.c
    int need_resolve = 1;
    if (sys_no == SYS_unlinkat || sys_no == SYS_readlinkat || sys_no == SYS_renameat) {
        need_resolve = 0;
    } else if (sys_no == SYS_openat) {
        int flags = (int)args[2];
        if (flags & O_NOFOLLOW)
            need_resolve = 0;
    } else if (sys_no == SYS_newfstatat || sys_no == SYS_faccessat) {
        int flags = (int)args[3];
        if (flags & AT_SYMLINK_NOFOLLOW) {
            need_resolve = 0;
        }
    }

    if (need_resolve) {
        if (resolve_symlink_chain_at(AT_FDCWD, rw_path, resolve_buf, sizeof(resolve_buf))) {
            rw_path = resolve_buf;
        }
    }

    result.path = rw_path;
    result.error = 0;
    return result;
}

// A scratch buffer for overlay resolution within this module.
static char g_overlay_path[CONFIG_MAX_PATH];
static char g_resolve_buf[CONFIG_MAX_PATH];

vfs_path_result_t vfs_resolve(const char *virt_path, long sys_no, long *args) {
    vfs_path_result_t result;
    vfs_ensure_init();

    if (!virt_path) {
        result.path = virt_path;
        result.error = 0;
        return result;
    }

    char virt_abs_buf[CONFIG_MAX_PATH];
    const char *virt_abs = vfs_abspath(virt_path, virt_abs_buf, sizeof(virt_abs_buf));
    if (log_debug_enabled()) {
        char sys_buf[32];
        format_int(sys_no, sys_buf, sizeof(sys_buf));
        log_path_pair("[VFS] resolve sys ", sys_buf, virt_abs);
    }

    struct vfs_overlay_match match;
    if (!vfs_match_overlay(virt_abs, &match)) {
        vfs_path_result_t rewritten = vfs_resolve_rewrite(virt_path, sys_no, args);
        if (log_debug_enabled())
            log_path_pair("[VFS] resolve rewrite ", virt_abs, rewritten.path);
        return rewritten;
    }

    char upper_buf[CONFIG_MAX_PATH];
    char lower_buf[CONFIG_MAX_PATH];
    const char *upper_path = vfs_build_layer_path(match.upper_root, virt_abs,
                                                  upper_buf, sizeof(upper_buf));
    const char *lower_path = vfs_build_layer_path(match.lower_root, virt_abs,
                                                  lower_buf, sizeof(lower_buf));

    int exists_upper = upper_path ? path_exists(upper_path) : 0;
    int exists_lower = lower_path ? path_exists(lower_path) : 0;

    lnode_t *node = vfs_get_lnode(virt_abs);
    if (node) {
        node->exists_upper = exists_upper;
        node->exists_lower = exists_lower;
        if (exists_upper && exists_lower)
            node->status = LNODE_MERGED;
        else if (exists_upper)
            node->status = LNODE_IN_UPPER;
        else if (exists_lower)
            node->status = LNODE_IN_LOWER;
        else
            node->status = LNODE_UNKNOWN;
    }

    const char *chosen = NULL;
    int write_intent = vfs_is_write_intent(sys_no, args);
    if (write_intent) {
        chosen = upper_path ? upper_path : lower_path;
    } else {
        chosen = exists_upper ? upper_path : (exists_lower ? lower_path : NULL);
    }

    if (!chosen) {
        result.path = virt_path;
        result.error = -ENOENT;
        return result;
    }

    if (log_debug_enabled()) {
        if (chosen == upper_path) {
            log_path_pair("[VFS] resolve upper ", virt_abs, chosen);
        } else {
            log_path_pair("[VFS] resolve lower ", virt_abs, chosen);
        }
    }

    safe_cpy(g_overlay_path, sizeof(g_overlay_path), chosen);

    // Symlink resolution logic, moved from syscall_hooks.c
    int need_resolve = 1;
    if (sys_no == SYS_unlinkat || sys_no == SYS_readlinkat || sys_no == SYS_renameat) {
        need_resolve = 0;
    } else if (sys_no == SYS_openat) {
        int flags = (int)args[2];
        if (flags & O_NOFOLLOW)
            need_resolve = 0;
    } else if (sys_no == SYS_newfstatat || sys_no == SYS_faccessat) {
        int flags = (int)args[3];
        if (flags & AT_SYMLINK_NOFOLLOW) {
            need_resolve = 0;
        }
    }

    if (need_resolve) {
        if (resolve_symlink_chain_at(AT_FDCWD, g_overlay_path, g_resolve_buf, sizeof(g_resolve_buf))) {
            result.path = g_resolve_buf;
        } else {
            result.path = g_overlay_path;
        }
    } else {
        result.path = g_overlay_path;
    }

    result.error = 0;
    return result;
}

const char *vfs_reverse_path(const char *host_path, char *out, size_t out_sz)
{
    vfs_ensure_init();
    if (!host_path || !out || out_sz == 0)
        return host_path;
    if (vfs_host_to_virt(host_path, out, out_sz))
        return out;
    return rewrite_path_from_host(host_path, out, out_sz);
}

vfs_path_result_t vfs_rewrite_noresolve(const char *virt_path, char *out, size_t out_sz)
{
    vfs_path_result_t result;
    vfs_ensure_init();
    if (!virt_path || !out || out_sz == 0) {
        result.path = virt_path;
        result.error = 0;
        return result;
    }

    char virt_abs_buf[CONFIG_MAX_PATH];
    const char *virt_abs = vfs_abspath(virt_path, virt_abs_buf, sizeof(virt_abs_buf));
    struct vfs_overlay_match match;
    if (!vfs_match_overlay(virt_abs, &match)) {
        result.path = rewrite_path(virt_path, out, out_sz);
        result.error = 0;
        return result;
    }

    const char *upper_path = vfs_build_layer_path(match.upper_root, virt_abs, out, out_sz);
    if (!upper_path)
        upper_path = vfs_build_layer_path(match.lower_root, virt_abs, out, out_sz);
    result.path = upper_path ? upper_path : virt_path;
    result.error = upper_path ? 0 : -ENOENT;
    return result;
}

struct linux_dirent64 {
    unsigned long long d_ino;
    unsigned long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define D_NAME_OFFSET ((size_t)(&((struct linux_dirent64 *)0)->d_name))

static size_t vfs_dirent_reclen(const char *name)
{
    size_t name_len = sys_strlen(name);
    size_t reclen = D_NAME_OFFSET + name_len + 1;
    return (reclen + 7) & ~((size_t)7);
}

static int vfs_is_whiteout(const char *name)
{
    return name && name[0] == '.' && name[1] == 'w' && name[2] == 'h' &&
           name[3] == '.' && name[4] != '\0';
}

static int vfs_find_entry(struct vfs_dir_cache *cache, const char *name)
{
    if (!cache || !name)
        return -1;
    for (size_t i = 0; i < cache->count; i++) {
        if (sys_streq(cache->entries[i].name, name))
            return (int)i;
    }
    return -1;
}

static int vfs_add_entry(struct vfs_dir_cache *cache, const char *name,
                         unsigned long ino, unsigned char type, int from_upper)
{
    if (!cache || !name)
        return 0;
    if (cache->count >= VFS_MAX_DENTS)
        return 0;
    safe_cpy(cache->entries[cache->count].name,
             sizeof(cache->entries[cache->count].name),
             name);
    cache->entries[cache->count].ino = ino;
    cache->entries[cache->count].type = type;
    cache->entries[cache->count].from_upper = from_upper;
    cache->entries[cache->count].hidden = 0;
    cache->count++;
    return 1;
}

static void vfs_apply_whiteouts(struct vfs_dir_cache *cache,
                                char whiteouts[][CONFIG_MAX_PATH],
                                size_t whiteout_count)
{
    if (!cache)
        return;
    for (size_t i = 0; i < whiteout_count; i++) {
        int idx = vfs_find_entry(cache, whiteouts[i]);
        if (idx >= 0)
            cache->entries[idx].hidden = 1;
    }
    size_t out = 0;
    for (size_t i = 0; i < cache->count; i++) {
        if (cache->entries[i].hidden)
            continue;
        if (out != i)
            cache->entries[out] = cache->entries[i];
        out++;
    }
    cache->count = out;
}

static int vfs_read_dir_entries(const char *path, struct vfs_dir_cache *cache,
                                int from_upper,
                                char whiteouts[][CONFIG_MAX_PATH],
                                size_t *whiteout_count)
{
    if (!path || !cache)
        return 0;
    size_t count_before = cache->count;
    size_t whiteout_before = whiteout_count ? *whiteout_count : 0;
    long fd = raw_syscall(SYS_openat, AT_FDCWD, (long)path,
                          O_RDONLY | O_DIRECTORY, 0, 0, 0);
    if (fd < 0) {
        long retry = raw_syscall(SYS_openat, AT_FDCWD, (long)path,
                                 O_RDONLY, 0, 0, 0);
        if (retry >= 0) {
            fd = retry;
            if (log_debug_enabled())
                log_path_pair("[VFS] readdir open fallback ", path, NULL);
        } else if (log_debug_enabled()) {
            log_path_pair("[VFS] readdir open fail ", path, NULL);
            log_errno_value("[VFS] readdir errno ", -retry);
        }
    } else if (log_debug_enabled()) {
        log_path_pair("[VFS] readdir open ", path, NULL);
    }

    if (fd < 0)
        return 0;

    char buf[VFS_DENT_BUF];
    for (;;) {
        long n = raw_syscall(SYS_getdents64, fd, (long)buf,
                             sizeof(buf), 0, 0, 0);
        if (n <= 0)
            break;
        size_t pos = 0;
        while (pos < (size_t)n) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + pos);
            if (d->d_reclen == 0)
                break;
            const char *name = d->d_name;
            if (!sys_streq(name, ".") && !sys_streq(name, "..")) {
                if (from_upper && vfs_is_whiteout(name)) {
                    if (whiteout_count && *whiteout_count < VFS_MAX_DENTS) {
                        safe_cpy(whiteouts[*whiteout_count],
                                 CONFIG_MAX_PATH, name + 4);
                        (*whiteout_count)++;
                    }
                } else {
                    int idx = vfs_find_entry(cache, name);
                    if (idx >= 0) {
                        cache->entries[idx].ino = d->d_ino;
                        cache->entries[idx].type = d->d_type;
                        cache->entries[idx].from_upper = from_upper;
                        cache->entries[idx].hidden = 0;
                    } else {
                        vfs_add_entry(cache, name, d->d_ino, d->d_type, from_upper);
                    }
                }
            }
            pos += d->d_reclen;
        }
    }
    raw_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    if (log_debug_enabled()) {
        char add_buf[32];
        char wh_buf[32];
        size_t added = cache->count - count_before;
        size_t wh_added = whiteout_count ? (*whiteout_count - whiteout_before) : 0;
        format_int((int)added, add_buf, sizeof(add_buf));
        log_path_pair("[VFS] readdir added ", path, add_buf);
        format_int((int)wh_added, wh_buf, sizeof(wh_buf));
        log_path_pair("[VFS] readdir whiteout ", path, wh_buf);
    }
    return 1;
}

static int vfs_fd_to_virt_path(int fd, char *out, size_t out_sz)
{
    if (!out || out_sz == 0 || fd < 0)
        return 0;
    char fd_path[64];
    if (!format_fd_path(fd_path, sizeof(fd_path), fd))
        return 0;
    char host_path[CONFIG_MAX_PATH];
    long n = raw_syscall(SYS_readlinkat, AT_FDCWD, (long)fd_path,
                         (long)host_path, sizeof(host_path) - 1, 0, 0);
    if (n < 0)
        return 0;
    if ((size_t)n >= sizeof(host_path))
        n = sizeof(host_path) - 1;
    host_path[n] = '\0';
    vfs_reverse_path(host_path, out, out_sz);
    if (log_debug_enabled())
        log_path_pair("[VFS] fd map ", host_path, out);
    return 1;
}

static struct vfs_dir_cache *vfs_cache_get(int fd)
{
    for (int i = 0; i < VFS_MAX_DIR_CACHE; i++) {
        if (g_dir_cache[i].fd == fd)
            return &g_dir_cache[i];
    }
    return NULL;
}

static struct vfs_dir_cache *vfs_cache_alloc(int fd)
{
    for (int i = 0; i < VFS_MAX_DIR_CACHE; i++) {
        if (g_dir_cache[i].fd < 0) {
            g_dir_cache[i].fd = fd;
            g_dir_cache[i].count = 0;
            g_dir_cache[i].pos = 0;
            g_dir_cache[i].virt_path[0] = '\0';
            return &g_dir_cache[i];
        }
    }
    g_dir_cache[0].fd = fd;
    g_dir_cache[0].count = 0;
    g_dir_cache[0].pos = 0;
    g_dir_cache[0].virt_path[0] = '\0';
    return &g_dir_cache[0];
}

static long vfs_emit_dirents(struct vfs_dir_cache *cache, void *dirp,
                             unsigned int count)
{
    if (!cache || !dirp)
        return -EINVAL;
    if (cache->pos >= cache->count) {
        cache->fd = -1;
        cache->count = 0;
        cache->pos = 0;
        return 0;
    }

    unsigned char *out = (unsigned char *)dirp;
    size_t written = 0;
    while (cache->pos < cache->count) {
        struct vfs_dir_entry *ent = &cache->entries[cache->pos];
        size_t reclen = vfs_dirent_reclen(ent->name);
        if (written + reclen > (size_t)count)
            break;
        struct linux_dirent64 *d = (struct linux_dirent64 *)(out + written);
        d->d_ino = ent->ino;
        d->d_off = (unsigned long long)(cache->pos + 1);
        d->d_reclen = (unsigned short)reclen;
        d->d_type = ent->type;
        safe_cpy(d->d_name, reclen - D_NAME_OFFSET, ent->name);
        written += reclen;
        cache->pos++;
    }

    if (written == 0)
        return -EINVAL;
    if (cache->pos >= cache->count) {
        cache->fd = -1;
        cache->count = 0;
        cache->pos = 0;
    }
    return (long)written;
}

long vfs_getdents64(int fd, void *dirp, unsigned int count)
{
    vfs_ensure_init();
    char fd_buf[32];
    int fd_buf_valid = 0;
    if (log_debug_enabled()) {
        format_int(fd, fd_buf, sizeof(fd_buf));
        fd_buf_valid = 1;
        log_path_pair("[VFS] getdents fd ", fd_buf, NULL);
    }

    char virt_path[CONFIG_MAX_PATH];
    int have_virt = vfs_fd_to_virt_path(fd, virt_path, sizeof(virt_path));

    struct vfs_dir_cache *cache = vfs_cache_get(fd);
    if (cache && have_virt) {
        if (cache->virt_path[0] == '\0' || !sys_streq(cache->virt_path, virt_path)) {
            if (log_debug_enabled())
                log_path_pair("[VFS] cache mismatch ", cache->virt_path, virt_path);
            cache->fd = -1;
            cache->count = 0;
            cache->pos = 0;
            cache->virt_path[0] = '\0';
            cache = NULL;
        }
    } else if (cache && !have_virt) {
        if (log_debug_enabled()) {
            if (!fd_buf_valid) {
                format_int(fd, fd_buf, sizeof(fd_buf));
                fd_buf_valid = 1;
            }
            log_path_pair("[VFS] cache drop fd ", fd_buf, NULL);
        }
        cache->fd = -1;
        cache->count = 0;
        cache->pos = 0;
        cache->virt_path[0] = '\0';
        cache = NULL;
    }

    if (!cache) {
        if (!have_virt) {
            return raw_syscall(SYS_getdents64, fd, (long)dirp, count, 0, 0, 0);
        }

        struct vfs_overlay_match match;
        if (!vfs_match_overlay(virt_path, &match)) {
            return raw_syscall(SYS_getdents64, fd, (long)dirp, count, 0, 0, 0);
        }
        if (log_debug_enabled())
            log_path_pair("[VFS] getdents mount ", match.mount, virt_path);

        cache = vfs_cache_alloc(fd);
        if (!cache)
            return raw_syscall(SYS_getdents64, fd, (long)dirp, count, 0, 0, 0);
        safe_cpy(cache->virt_path, sizeof(cache->virt_path), virt_path);

        char upper_buf[CONFIG_MAX_PATH];
        char lower_buf[CONFIG_MAX_PATH];
        const char *upper_path = vfs_build_layer_path(match.upper_root, virt_path,
                                                      upper_buf, sizeof(upper_buf));
        const char *lower_path = vfs_build_layer_path(match.lower_root, virt_path,
                                                      lower_buf, sizeof(lower_buf));
        if (log_debug_enabled()) {
            if (lower_path)
                log_path_pair("[VFS] getdents lower ", virt_path, lower_path);
            if (upper_path)
                log_path_pair("[VFS] getdents upper ", virt_path, upper_path);
        }

        char whiteouts[VFS_MAX_DENTS][CONFIG_MAX_PATH];
        size_t whiteout_count = 0;

        if (lower_path)
            vfs_read_dir_entries(lower_path, cache, 0, whiteouts, &whiteout_count);
        if (upper_path)
            vfs_read_dir_entries(upper_path, cache, 1, whiteouts, &whiteout_count);

        vfs_apply_whiteouts(cache, whiteouts, whiteout_count);
        if (cache->count == 0) {
            if (log_debug_enabled())
                log_message(LOG_LEVEL_DEBUG, "[VFS] getdents empty, fallback\n");
            cache->fd = -1;
            cache->count = 0;
            cache->pos = 0;
            return raw_syscall(SYS_getdents64, fd, (long)dirp, count, 0, 0, 0);
        }
    }

    return vfs_emit_dirents(cache, dirp, count);
}

// --- Identity & Permission Faking APIs ---

int vfs_getuid(void) { return 0; }
int vfs_geteuid(void) { return 0; }
int vfs_getgid(void) { return 0; }
int vfs_getegid(void) { return 0; }

int vfs_getresuid(int *ruid, int *euid, int *suid) {
    if (ruid) *ruid = 0;
    if (euid) *euid = 0;
    if (suid) *suid = 0;
    return 0;
}

int vfs_getresgid(int *rgid, int *egid, int *sgid) {
    if (rgid) *rgid = 0;
    if (egid) *egid = 0;
    if (sgid) *sgid = 0;
    return 0;
}

int vfs_getgroups(int size, int list[]) {
    if (list && size > 0) {
        list[0] = 0; // root group
    }
    return (size > 0) ? 1 : 0;
}

int vfs_fake_success(void) {
    return 0;
}
