/* SPDX-License-Identifier: GPL-2.0-or-later */
/* State shared by every process of one container view (docs/OCI.md):
 * the mount table (R4) and the owner database (R5). Both are files mapped
 * MAP_SHARED, inherited as reserved FDs (CONFIG_MOUNT_TABLE_FD,
 * CONFIG_OWNER_DB_FD) across fork and exec.
 *
 * Neither is a security boundary, by design: in isolation mode the broker
 * decides what a host path may reach from its own trees only, never from
 * these tables, so a guest that rewrites them changes only what it sees
 * (its view, the owners it reports), never what it can touch. */
#ifndef CONTAINER_STATE_H
#define CONTAINER_STATE_H
#include <stdint.h>
#include <asm/stat.h>
#include "config.h"

/* ---- R4: mounts made inside the container ----
 * The payload appends the slots to the configured binds of every path
 * lookup: slot i is mount id bind_count + 1 + i, stable while it lives (an
 * FD's or the cwd's recorded mount stays meaningful). A free slot (empty
 * guest) never matches. A mount hides every older one below or at its
 * mountpoint (a stack, as in the kernel); older means configured binds,
 * then smaller id. Writers hold lock and make version odd while writing;
 * readers copy the entries and retry if version moved. */
#define MOUNT_TABLE_MAX CONFIG_MAX_MOUNTS
enum mount_kind {
    MOUNT_BIND = 1,  /* mount --bind: host is the source's host path */
    MOUNT_TMPFS,     /* a directory of its own under the mount scratch */
    MOUNT_HOST,      /* proc, sysfs, devpts...: the host's own directory */
    MOUNT_OVERLAY,   /* R6: host is the upperdir; the lowerdirs are in overlays[] */
};
struct mount_entry {
    char guest[CONFIG_MAX_PATH];  /* mountpoint, canonical guest path */
    char host[CONFIG_MAX_PATH];   /* what it shows */
    char source[64];              /* mount source, as /proc/self/mounts shows it */
    char fstype[16];
    uint32_t kind;
    uint32_t flags;               /* MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC... */
    uint32_t id;                  /* creation order, from next_id */
    uint32_t access;              /* guarded build: 'd', 'r' or 'w' */
};
/* The lowerdirs of an overlay mount (topmost first), by its entry's id; a
 * record whose id no live entry has is free. Kept apart from the entries:
 * every path call copies those. */
#define MOUNT_OVERLAYS 8
struct mount_overlay {
    uint32_t id, count;
    char lower[CONFIG_MAX_LOWERS][CONFIG_MAX_PATH];
    /* R6 mount -o loop: the layer image (lazy_layer.h) whose cache the
     * last lower is; empty for a plain overlay. */
    char image[CONFIG_MAX_PATH];
};
/* R6 loop devices /dev/loop0..7 (emulated: a loop mount of an erofs image
 * is a read-only merged view of its cache). A slot is bound to a backing
 * file by LOOP_SET_FD/LOOP_CONFIGURE and freed by LOOP_CLR_FD, or at the
 * umount of its last mount when it has LO_FLAGS_AUTOCLEAR. */
#define MOUNT_LOOPS 8
struct mount_loop {
    uint32_t bound, flags;          /* flags: LO_FLAGS_* */
    uint64_t offset, sizelimit, dev, ino, size;
    char file[CONFIG_MAX_PATH];     /* the backing file's host path */
    char name[64];                  /* lo_file_name */
};
struct mount_table {
    uint32_t lock, version, count, next_id;
    uint32_t overlays;   /* overlay mounts ever made: union views may exist */
    uint32_t reserved[11];
    struct mount_entry entries[MOUNT_TABLE_MAX];
    struct mount_overlay overlay[MOUNT_OVERLAYS];
    struct mount_loop loop[MOUNT_LOOPS];
};
#define MOUNT_TABLE_SIZE ((sizeof(struct mount_table) + 4095) & ~(unsigned long)4095)
_Static_assert(MOUNT_TABLE_SIZE == CONFIG_MOUNT_TABLE_BYTES, "the loader sizes the table");

int mounts_enabled(void);
/* Copies the used slots (count returned, at most max); free slots have an
 * empty guest. */
int mounts_snapshot(struct mount_entry *out, int max);
/* Whether entry i of a snapshot is hidden by a newer mount at or above its
 * mountpoint; a configured bind (guest path) by any live slot. */
int mounts_hidden(const struct mount_entry *entries, int count, int i);
int mounts_bind_hidden(const struct mount_entry *entries, int count, const char *guest);
/* Access of every used slot ('d' for a free one); the count. */
int mounts_access(char *out, int max);
/* Adds an entry (id assigned) in a free slot; -ENOMEM when full. An
 * overlay entry takes lowers (count of them), or with lowers NULL those of
 * the overlay whose id entry->id holds (a copy for --rbind). */
long mounts_add(const struct mount_entry *entry);
long mounts_add_overlay(const struct mount_entry *entry, const char (*lowers)[CONFIG_MAX_PATH], int count,
                        const char *image);
/* The lowerdirs of overlay mount id (count returned, at most max); image
 * (CONFIG_MAX_PATH, may be NULL): its layer image or "". */
int mounts_overlay_lowers(uint32_t id, char (*out)[CONFIG_MAX_PATH], int max, char *image);
/* Loop device n: a copy (0, or -ENXIO when unbound). */
long mounts_loop_get(int n, struct mount_loop *out);
/* Binds a free loop device (-EBUSY if bound); with in NULL frees it. */
long mounts_loop_bind(int n, const struct mount_loop *in);
/* Status change of a bound device: flags, offset, sizelimit, name. */
long mounts_loop_status(int n, const struct mount_loop *in);
/* The first unbound loop device, -ENOSPC if none. */
int mounts_loop_free(void);
/* Whether any overlay mount was ever made in this view. */
int mounts_overlays(void);
/* Frees the newest live slot at guest (with detach also every slot below
 * it; without, -EBUSY if any). 0, or -EINVAL if no slot is mounted there. */
long mounts_remove(const char *guest, int detach);
/* The newest live slot mounted at guest, -1 if none. */
int mounts_find(const struct mount_entry *entries, int count, const char *guest);
/* MS_REMOUNT of slot at guest: new flags. MS_MOVE: every slot at or below
 * from moves under to. */
long mounts_set_flags(const char *guest, uint32_t flags, uint32_t access);
long mounts_move(const char *from, const char *to);
/* /proc/<pid>/mounts (info 0) or mountinfo (info 1) into fd. */
long mounts_render(int fd, int info);
/* The filesystem name /proc/mounts shows for a host directory. */
const char *mounts_fs_name(const char *host);

/* ---- R5: owners and modes the host cannot hold ----
 * An open-addressing hash table keyed by (st_dev, st_ino) as struct stat
 * reports them. tools/oci/owners.py writes the same layout. A record with
 * OWNER_IDS reports uid/gid, with OWNER_MODE the permission bits; a DEAD
 * record keeps probe chains intact after a deletion. Writers hold lock and
 * make version odd while writing. */
#define OWNER_DB_MAGIC "ELFOWN1"
#define OWNER_USED 1u
#define OWNER_IDS  2u
#define OWNER_MODE 4u
#define OWNER_DEAD 8u
struct owner_db_header {
    char magic[8];
    uint32_t capacity;   /* records, a power of two */
    uint32_t count;      /* used slots, dead ones included */
    uint32_t lock;
    uint32_t version;
    uint32_t reserved[10];
};
struct owner_record {
    uint64_t dev, ino;
    uint32_t uid, gid, mode, flags;
};
_Static_assert(sizeof(struct owner_db_header) == 64 && sizeof(struct owner_record) == 32,
               "tools/oci/owners.py layout");
static inline uint64_t owner_hash(uint64_t dev, uint64_t ino)
{
    uint64_t h = ino * 0x9E3779B97F4A7C15ull ^ dev * 0xC2B2AE3D27D4EB4Full;
    return h ^ (h >> 29);
}

int owners_enabled(void);
/* After a successful fstat/newfstatat/statx: the recorded owner and mode. */
void owners_stat(long number, const long *args);
/* chown of the object st describes (-1 keeps an id): recorded, the host
 * file is not changed. -EPERM as the kernel would for an unprivileged
 * fake user. */
long owners_chown(const struct stat *st, long uid, long gid);
/* chmod: may the caller change the mode (0 or -EPERM). */
long owners_may_chmod(const struct stat *st);
/* The host mode to apply for a guest mode: owner rw (rwx for directories)
 * stay, as at unpacking. */
unsigned owners_host_mode(const struct stat *st, unsigned mode);
/* After the host chmod: host_mode was applied (the guest asked for mode). */
void owners_chmod_done(const struct stat *st, unsigned mode, unsigned host_mode);
/* A new object: owned by the fake fs ids. */
void owners_created(const struct stat *st);
/* The last name of an object is gone. */
void owners_forget(const struct stat *st);
/* R6 copy-up: to (the upper's copy) takes the record of from. */
void owners_copied(const struct stat *from, const struct stat *to);
/* Reported owner (no record: root for the user's own files). */
void owners_lookup(const struct stat *st, uint32_t *uid, uint32_t *gid, uint32_t *mode);

#endif
