/* SPDX-License-Identifier: GPL-2.0-or-later */
/* R6 (docs/OCI.md): a merged view of a writable upper directory over
 * read-only lower directories, as overlayfs shows it, emulated on host
 * paths. Layer 0 is the upper; the lowers follow, topmost first.
 *
 * Views: the root's (--lower) and one per overlay mount made inside the
 * container (mount -t overlay, R4's table: upperdir and lowerdirs). A host
 * path belongs to the view with the longest layer that holds it, whichever
 * guest path led there (a bind of a merged directory is merged too).
 *
 * Whiteouts are files named as in OCI layer tars: ".wh.<name>" hides
 * <name> of the layers below, ".wh..wh..opq" in a directory hides the
 * directory's contents below. So an upper directory is the layer diff
 * itself, and an unpacked layer can serve as a lower. Names beginning with
 * ".wh." are never visible in the view.
 *
 * Lookup takes the topmost layer that has a name (a non-directory or an
 * opaque directory ends the search there); a change to an object of a
 * lower layer first copies it up (with its parent directories); removal
 * of a name a lower layer has leaves a whiteout. Renaming a directory that
 * a lower layer has gives EXDEV, as overlayfs does without redirect_dir
 * (mv then copies). Directory listings merge the layers (getdents64).
 *
 * In isolation mode every host call goes to the broker, which gives the
 * lowers as read-only trees: the view is not a security boundary, the
 * lowers are protected by the trees. */
#ifndef UNION_VIEW_H
#define UNION_VIEW_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/limits.h>
#include "config.h"

#define UNION_LAYERS (1 + CONFIG_MAX_LOWERS)

struct union_view {
    int count;                        /* layers, upper included */
    const char *layer[UNION_LAYERS];  /* host directories, no trailing '/' */
    size_t length[UNION_LAYERS];
};

/* Where a name of the view is: the walk of one lookup. */
struct union_hit {
    int layer;       /* topmost layer holding the object, -1 if none */
    bool dir;        /* the object is a directory */
    bool below;      /* a layer other than the upper has it (removal leaves a whiteout) */
    bool whiteout;   /* the upper hides it with a whiteout */
    uint32_t dirs;   /* directory: the layers whose copies merge (bit per layer) */
};

/* Successive lookups of the same call share the walk of a common prefix. */
struct union_memo {
    bool valid;
    const void *view; /* the walk was of this view */
    size_t length;
    uint32_t mask;   /* layers where rel[0..length) is a visible directory */
    char rel[PATH_MAX];
};

/* The root's view (--lower): false without lowers. */
bool union_root(struct union_view *u);
/* Whether views can exist: lowers, or an overlay mount was made. */
bool union_enabled(void);
struct mount_entry;
/* Every view: the root's, then each live overlay mount of the snapshot
 * (whose host strings it points into; the lowerdirs are copied to
 * storage, CONFIG_MAX_LOWERS per overlay). The count. */
int union_views(struct union_view *views, int max, char (*storage)[CONFIG_MAX_PATH],
                const struct mount_entry *mounts, int mount_count);
/* The view holding host (its longest layer), -1 if none; *layer, *rel. */
int union_find(const struct union_view *views, int count, const char *host, int *layer, const char **rel);

/* Layer index whose tree holds host (-1 none) and the relative part. */
int union_layer_of(const struct union_view *u, const char *host, const char **rel);

/* host names an object below layer 0 (the upper) as the mount maps it:
 * rewritten to the layer that shows it; a missing or hidden name stays
 * below the upper (where a creation makes it). hit may be NULL. Returns 0
 * or -errno (ENAMETOOLONG). */
int union_map(const struct union_view *u, char host[PATH_MAX], struct union_hit *hit,
              struct union_memo *memo);

/* A host path in a lower layer, as the upper names the same guest path
 * (for reverse mapping); 1 if rewritten. */
int union_alias(const struct union_view *u, const char *host, char out[PATH_MAX]);

/* Copies the object at rel (and its parent directories) to the upper if
 * the view shows it from a lower; data false skips the content of a
 * regular file (it is about to be truncated). Returns 0 or -errno. */
long union_copy_up(const struct union_view *u, const char *rel, bool data);

/* Before creating rel: its parent directories in the upper, its whiteout
 * removed. *opaque tells whether a directory made there must be opaque
 * (a lower name was hidden there). -EEXIST if the view shows rel. */
long union_prepare_create(const struct union_view *u, const char *rel, bool *opaque);

/* After making a directory at rel over a hidden lower name. */
long union_make_opaque(const struct union_view *u, const char *rel);

/* unlink (dir false) or rmdir of rel. */
long union_remove(const struct union_view *u, const char *rel, bool dir);

/* rename of from to to (flags as renameat2). */
long union_rename(const struct union_view *u, const char *from, const char *to, unsigned flags);

/* getdents64 of fd after the kernel call returned ret: whiteouts removed
 * and, once the fd's own directory is exhausted, the entries of the
 * layers below that are not hidden. */
long union_getdents(int fd, void *buffer, unsigned long count, long ret);

/* A whiteout or opaque marker name. */
static inline bool union_hidden_name(const char *name)
{
    return name[0] == '.' && name[1] == 'w' && name[2] == 'h' && name[3] == '.';
}

#endif
