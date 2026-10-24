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

#include <sys/types.h>		/* pid_t */
#include <limits.h>		/* PATH_MAX, */
#include <sys/param.h>		/* MAXSYMLINKS, */
#include <errno.h>		/* E*, */
#include <sys/stat.h>		/* lstat(2), S_ISREG(), */
#include <unistd.h>		/* access(2), lstat(2), */
#include <string.h>		/* string(3), */
#include <assert.h>		/* assert(3), */
#include <stdio.h>		/* sscanf(3), */

#include "path/canon.h"
#include "path/path.h"
#include "path/binding.h"
#include "path/glue.h"
#include "path/proc.h"
#include "extension/extension.h"

#include "path/canon_core.h"

/**
 * Resolve bindings (if any) in @guest_path and copy the translated
 * path into @host_path.  Also, this function checks that a non-final
 * component is either a directory (returned value is 0) or a symlink
 * (returned value is 1), otherwise it returns -errno or -ENOTDIR.
 */
static inline int substitute_binding_stat(Tracee *tracee,
					  Finality finality,
					  unsigned int recursion_level,
					  const char guest_path[PATH_MAX],
					  char host_path[PATH_MAX])
{
    struct stat statl;
    int status;

    strcpy(host_path, guest_path);
    status = substitute_binding(tracee, GUEST, host_path);
    if (status < 0)
	return status;

    /* Don't notify extensions during the initialization of a binding.  */
    if (tracee->glue_type == 0) {
	status =
	    notify_extensions(tracee, HOST_PATH,
			      (intptr_t) host_path, IS_FINAL(finality)
			      && recursion_level == 0);
	if (status < 0)
	    return status;
    }

    statl.st_mode = 0;
    status = lstat(host_path, &statl);

    /* Build the glue between the hostfs and the guestfs during
     * the initialization of a binding.  */
    if (status < 0 && tracee->glue_type != 0) {
	statl.st_mode =
	    build_glue(tracee, guest_path, host_path, finality);
	if (statl.st_mode == 0)
	    status = -1;
    }

    /* Return an error if a non-final component isn't a directory
     * nor a symlink.  The error depends on why the component
     * could not be accessed (ENOENT, EACCES, ...), otherwise the
     * error is "Not a directory".  */
    if (!IS_FINAL(finality) && !S_ISDIR(statl.st_mode)
	&& !S_ISLNK(statl.st_mode))
	return (status < 0 ? -errno : -ENOTDIR);

    return (S_ISLNK(statl.st_mode) ? 1 : 0);
}


_Static_assert((int)DEFAULT == (int)FS_LINK_DEFAULT &&
               (int)CANONICALIZE == (int)FS_LINK_CANONICALIZE &&
               (int)DONT_CANONICALIZE == (int)FS_LINK_KEEP,
               "Legacy proc actions must match the core callback contract");

static int tracee_lookup(void *opaque, Finality finality, unsigned int level,
                         const char *guest, char *host)
{
    return substitute_binding_stat(opaque, finality, level, guest, host);
}
static int tracee_readlink(void *opaque, const char *path, char *out, size_t size)
{
    (void)opaque;
    ssize_t result = readlink(path, out, size);
    return result < 0 ? -errno : (int)result;
}
static int tracee_detranslate(void *opaque, char *path, const char *referrer)
{
    return detranslate_path(opaque, path, referrer);
}
static int tracee_proc_link(void *opaque, char *out, const char *path,
                            const char *component, Comparison comparison)
{
    return readlink_proc(opaque, out, path, component, comparison);
}
int canonicalize(Tracee *tracee, const char *path, bool deref_final,
                 char guest[PATH_MAX], unsigned int level)
{
    static const PathOps ops = {
        tracee_lookup, tracee_readlink, tracee_detranslate, tracee_proc_link
    };
    PathContext ctx = { tracee, &ops };
    return canonicalize_core(&ctx, path, deref_final, guest, level);
}
