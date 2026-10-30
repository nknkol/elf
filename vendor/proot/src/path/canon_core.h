/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#ifndef PROOT_CANON_CORE_H
#define PROOT_CANON_CORE_H
#include <stdbool.h>
#include "path/path_types.h"

/* Callbacks return negative errno on failure. Paths are caller-owned buffers.
 * lookup returns 1 for symlinks, 0 otherwise; it must enforce intermediate
 * directory existence, but may defer final-component errors to the syscall.
 * readlink returns a byte count without NUL; proc_link returns the action below.
 * Callbacks must bypass guest syscall interception in an SVC implementation.
 */
enum { FS_LINK_DEFAULT, FS_LINK_CANONICALIZE, FS_LINK_KEEP };
#include <sys/param.h>
#include <limits.h>

typedef struct {
    int (*lookup)(void *, Finality, unsigned int, const char *, char *);
    int (*readlink)(void *, const char *, char *, size_t);
    int (*detranslate)(void *, char *, const char *);
    int (*proc_link)(void *, char *, const char *, const char *, Comparison);
    /* Optional: rewrite a guest path in place (same length) to the exact
     * spelling of the mountpoint it names, before it is looked up. */
    void (*respell)(void *, char *);
} PathOps;
/* Per-recursion-level scratch: one per followed symlink. */
typedef struct {
    char scratch[PATH_MAX], host[PATH_MAX], component[NAME_MAX];
} PathFrame;
/* Levels 0..CANON_LEVELS-1; one more is ELOOP. */
#define CANON_LEVELS (MAXSYMLINKS + 1)
typedef struct {
    void *opaque;
    const PathOps *ops;
    /* Optional scratch off the stack, so a caller on a small stack (a vfork
     * child's spawn stack) pays no stack per followed symlink: frames for
     * the first levels, and deep(), when set, returns frames for levels
     * frame_count..CANON_LEVELS-1 (NULL: -ENOMEM). Without either, frames
     * come from the stack. */
    PathFrame *frames;
    unsigned int frame_count;
    PathFrame *(*deep)(void *opaque);
} PathContext;

int canonicalize_core(PathContext *, const char *, bool, char [PATH_MAX], unsigned int);
#endif
