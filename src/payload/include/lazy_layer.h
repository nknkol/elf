/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Layer images (docs/OCI.md, R6 "层镜像"): a lower layer stored as an erofs
 * image file (uncompressed: flat plain and flat inline data) and expanded
 * on demand into a cache directory that serves as the layer's directory.
 * The guest only ever gets kernel objects of the cache.
 *
 * The cache protocol (tools/oci/erofs.py implements the same):
 *  - A directory of the cache is expanded when it holds LAZY_MARKER. Its
 *    expansion (under flock of the directory) makes every child: a
 *    directory (empty, unexpanded; mode | 0700 as copy-up makes it), a
 *    symlink, a FIFO (skipped where the storage refuses it), or a regular
 *    file. Devices and sockets are skipped, as unpacking skips them; hard
 *    links become separate files. Each child but a FIFO is made under
 *    LAZY_TMP and renamed into place, so a name that exists is complete (a
 *    FIFO has no content; it is made at its name, since some storage
 *    refuses to rename one).
 *  - A regular file with content starts as a placeholder: sparse, with the
 *    image's size, mode and mtime, and an atime of LAZY_ATIME (far in the
 *    future, which relatime never replaces). Before its content is read it
 *    is filled in place (same inode: owner records keyed by inode stay
 *    valid), under flock of the file, and its atime set to the mtime.
 *  - Names beginning with ".wh..elf-" are the protocol's own; ".wh." names
 *    of the image are whiteouts of the layer below, as in an upper.
 *
 * Every path below the cache is walked one component at a time with
 * O_NOFOLLOW: a symlink of the image never leads the expansion outside the
 * cache. Image contents are checked against the image's bounds. */
#ifndef LAZY_LAYER_H
#define LAZY_LAYER_H
#include <stdbool.h>
#include <stdint.h>

#define LAZY_MARKER ".wh..elf-lazy"
#define LAZY_TMP ".wh..elf-lazy-tmp"
#define LAZY_ATIME_SEC 15000000000L
#define LAZY_ATIME_NSEC 123456789L

/* Expands the directory at rel ("" for the top, else "/a/b") of the cache
 * from the image. 0 or -errno (-ENOENT/-ENOTDIR: no such directory in the
 * image). */
long lazy_expand(const char *image, const char *cache, const char *rel);

/* Fills the regular file at rel if it is a placeholder. 0 or -errno. */
long lazy_fill(const char *image, const char *cache, const char *rel);

/* Expands every directory on the way to rel (and rel itself when it is a
 * directory); fill: also fills rel when it is a regular file. A name the
 * image lacks is not an error (0). */
long lazy_ensure(const char *image, const char *cache, const char *rel, bool fill);

/* Whether the times of a stat result mark a placeholder. */
static inline bool lazy_placeholder_times(long atime_sec, long atime_nsec)
{
    return atime_sec == LAZY_ATIME_SEC && atime_nsec == LAZY_ATIME_NSEC;
}

/* A name of the protocol (never shown: union_hidden_name covers ".wh."). */
static inline bool lazy_own_name(const char *name)
{
    const char *p = ".wh..elf-";
    for (int i = 0; p[i]; i++)
        if (name[i] != p[i]) return false;
    return true;
}

#endif
