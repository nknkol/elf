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

#ifndef PROOT_PATH_TYPES_H
#define PROOT_PATH_TYPES_H
#include <limits.h>
#ifndef PATH_MAX
/* Clang freestanding limits.h omits the libc pathname limits. */
#include <linux/limits.h>
#endif
#include <stddef.h>
#include <stdbool.h>
/* File type.  */
typedef enum {
    REGULAR,
    SYMLINK,
} Type;

/* Path point-of-view.  */
typedef enum {
    GUEST,
    HOST,

    /* Used for bindings as specified by the user but not
     * canonicalized yet (new_binding, initialize_binding).  */
    PENDING,
} Side;

/* Path with cached attributes.  */
typedef struct {
    char path[PATH_MAX];
    size_t length;
    Side side;
} Path;

/* Path ending type.  */
typedef enum {
    NOT_FINAL,
    FINAL_NORMAL,
    FINAL_SLASH,
    FINAL_DOT
} Finality;

#define IS_FINAL(a) ((a) != NOT_FINAL)

/* Comparison between two paths.  */
typedef enum Comparison {
    PATHS_ARE_EQUAL,
    PATH1_IS_PREFIX,
    PATH2_IS_PREFIX,
    PATHS_ARE_NOT_COMPARABLE,
} Comparison;


int join_paths(int count, char result[PATH_MAX], ...);
Comparison compare_paths(const char *, const char *);
Comparison compare_paths2(const char *, size_t, const char *, size_t);
#endif
