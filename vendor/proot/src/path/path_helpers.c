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

#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "path/path_types.h"

int join_paths(int number_paths, char result[PATH_MAX], ...)
{
    va_list paths;
    size_t length;
    int status;
    int i;

    result[0] = '\0';
    length = 0;
    status = 0;

    /* Parse the list of variadic arguments. */
    va_start(paths, result);
    for (i = 0; i < number_paths; i++) {
	const char *path;
	size_t path_length;
	size_t new_length;

	path = va_arg(paths, const char *);
	if (path == NULL)
	    continue;
	path_length = strlen(path);

	/* A new path separator is needed.  */
	if (length > 0 && result[length - 1] != '/' && path[0] != '/') {
	    new_length = length + path_length + 1;
	    if (new_length + 1 >= PATH_MAX) {
		status = -ENAMETOOLONG;
		break;
	    }
	    strcat(result + length, "/");
	    strcat(result + length, path);
	    length = new_length;
	}
	/* There are already two path separators.  */
	else if (length > 0 && result[length - 1] == '/' && path[0] == '/') {
	    new_length = length + path_length - 1;
	    if (new_length + 1 >= PATH_MAX) {
		status = -ENAMETOOLONG;
		break;
	    }
	    strcat(result + length, path + 1);
	    length += path_length - 1;
	}
	/* There's already one path separator or result[] is empty.  */
	else {
	    new_length = length + path_length;
	    if (new_length + 1 >= PATH_MAX) {
		status = -ENAMETOOLONG;
		break;
	    }
	    strcat(result + length, path);
	    length += path_length;
	}

	status = 0;
    }
    va_end(paths);

    return status;
}

Comparison
compare_paths2(const char *path1, size_t length1, const char *path2,
	       size_t length2)
{
    size_t length_min;
    bool is_prefix;
    char sentinel;

#if defined DEBUG_OPATH
    assert(strlen(path1) == length1);
    assert(strlen(path2) == length2);
#endif

    /* If either path is empty, they cannot be compared as paths. */
    if (length1 == 0 || length2 == 0) {
	return PATHS_ARE_NOT_COMPARABLE;
    }

    /* Remove potential trailing '/' for the comparison.  */
    if (path1[length1 - 1] == '/')
	length1--;

    if (path2[length2 - 1] == '/')
	length2--;

    if (length1 < length2) {
	length_min = length1;
	sentinel = path2[length_min];
    } else {
	length_min = length2;
	sentinel = path1[length_min];
    }

    /* Optimize obvious cases.  */
    if (sentinel != '/' && sentinel != '\0')
	return PATHS_ARE_NOT_COMPARABLE;

    is_prefix = (strncmp(path1, path2, length_min) == 0);

    if (!is_prefix)
	return PATHS_ARE_NOT_COMPARABLE;

    if (length1 == length2)
	return PATHS_ARE_EQUAL;
    else if (length1 < length2)
	return PATH1_IS_PREFIX;
    else if (length1 > length2)
	return PATH2_IS_PREFIX;

    assert(0);
    return PATHS_ARE_NOT_COMPARABLE;
}

Comparison compare_paths(const char *path1, const char *path2)
{
    return compare_paths2(path1, strlen(path1), path2, strlen(path2));
}
