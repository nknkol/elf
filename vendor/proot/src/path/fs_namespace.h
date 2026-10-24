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

#ifndef PROOT_FS_NAMESPACE_H
#define PROOT_FS_NAMESPACE_H

/* Shared filesystem state, independent of ptrace and register layout.
 * Ownership and allocation remain with the caller. No locking is implied.
 */
struct bindings;

/* Information related to a file-system name-space.  */
typedef struct {
    struct {
	/* List of bindings as specified by the user but not canonicalized yet.  */
	struct bindings *pending;

	/* List of bindings canonicalized and sorted in the "guest" order.  */
	struct bindings *guest;

	/* List of bindings canonicalized and sorted in the "host" order.  */
	struct bindings *host;
    } bindings;

    /* Current working directory, à la /proc/self/pwd.  */
    char *cwd;
} FileSystemNameSpace;

#endif /* PROOT_FS_NAMESPACE_H */
