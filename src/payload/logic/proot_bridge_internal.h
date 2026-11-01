/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Internal to the PRoot path backend: the per-call Bridge and the helpers
 * its parts share. proot_bridge.c (path translation, dispatch, bridge
 * lifecycle), proot_mounts.c (R4 mount table, tmpfs, loop devices,
 * overlay, /proc/filesystems), proot_procfs.c (/proc links, cmdline,
 * mount tables). Not a public interface: include only from these. */
#ifndef PROOT_BRIDGE_INTERNAL_H
#define PROOT_BRIDGE_INTERNAL_H
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

/* Shared between the parts (pb_: proot bridge). */
/* The guest of a bind the container unmounted: compared by address. */
extern const char pb_unmounted[];
#define UNMOUNTED pb_unmounted
int pb_resolve(Bridge *b, int dirfd, const char *path, bool follow);
int pb_bridge_alias(Bridge *b, const char *host, char *out);
int pb_guest_link_target(Bridge *b, char *target);
int pb_host_readlink(void *opaque, const char *path, char *out, size_t size);
int pb_loop_device(const char *guest);
long pb_loop_path_call(long number, long a[6], int device);
long pb_mount_call(Bridge *b, long a[6]);
long pb_umount_call(Bridge *b, long a[6]);
long pb_proc_filesystems(Bridge *b, int flags);
long pb_proc_cmdline(Bridge *b, int flags);
int pb_proc_link(void *opaque, char *out, const char *path, const char *component, Comparison comparison);
long pb_proc_mounts(Bridge *b, int flags);
long pb_proc_readlink(Bridge *b, long a[6]);

#endif
