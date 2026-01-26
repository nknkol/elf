#ifndef VFS_CORE_H
#define VFS_CORE_H

#include <stddef.h> // For size_t
#include "config.h"
#include "radix_tree.h"

typedef enum {
    LNODE_UNKNOWN = 0,
    LNODE_IN_LOWER,
    LNODE_IN_UPPER,
    LNODE_MERGED,
    LNODE_WHITEOUT
} lnode_status_t;

typedef struct lnode {
    char virt_path[CONFIG_MAX_PATH];
    lnode_status_t status;
    int exists_lower;
    int exists_upper;
} lnode_t;

typedef struct vfs_state {
    char lower_root[CONFIG_MAX_PATH];
    char upper_root[CONFIG_MAX_PATH];
    int overlay_count;
    struct overlay_entry overlays[CONFIG_MAX_OVERLAYS];
    radix_tree_t tree;
} vfs_state_t;

// A result structure for path resolution operations.
typedef struct vfs_path_result {
    const char *path; // The resolved real path.
    int error;        // 0 on success, or a negative errno value.
} vfs_path_result_t;

// Initializes the VFS core. (Currently a placeholder)
int vfs_core_init(const payload_config_t *config);

// Destroys the VFS core. (Currently a placeholder)
void vfs_core_destroy(void);

// Resolves a virtual path to a real path, handling path rewriting and symlinks.
// This is the main entry point for most filesystem syscalls.
vfs_path_result_t vfs_resolve(const char *virt_path, long sys_no, long *args);

// Reverse-maps a host path to a virtual path (e.g., getcwd/readlinkat).
const char *vfs_reverse_path(const char *host_path, char *out, size_t out_sz);

// Rewrites a virtual path without resolving symlinks (e.g., symlink target).
vfs_path_result_t vfs_rewrite_noresolve(const char *virt_path, char *out, size_t out_sz);

// Merges upper/lower directory entries and writes them into user buffer.
long vfs_getdents64(int fd, void *dirp, unsigned int count);

// Expose lower-level function needed by execve handler for now.
int resolve_symlink_chain_at(long dirfd, const char *path, char *out, size_t out_sz);

// --- Identity & Permission Faking APIs ---

int vfs_getuid(void);
int vfs_geteuid(void);
int vfs_getgid(void);
int vfs_getegid(void);
int vfs_getresuid(int *ruid, int *euid, int *suid);
int vfs_getresgid(int *rgid, int *egid, int *sgid);
int vfs_getgroups(int size, int list[]);

// All permission-setting syscalls are faked to return success (0).
int vfs_fake_success(void);

#endif /* VFS_CORE_H */
