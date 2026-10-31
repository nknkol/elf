/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolation mode, GPU devices (docs/ISOLATION.md, "GPU 设备"). The guest
 * filter cannot read a path, only compare a pointer: openat is let through
 * when its path is one of the selected constants below, at their fixed
 * address in this static non-PIE binary. They sit alone in one page-aligned
 * read-only page, so the filter guards just that page against every memory
 * call that could replace it; its content comes from the loader file, which
 * the broker never lets the guest write. execveat names the same page's
 * empty string. */
#include "loader.h"

const union isolate_page g_isolate_page
	__attribute__((section(".rodata.isolate"), aligned(4096), used)) = {
	.table = {
		.magic = ISOLATE_PAGE_MAGIC,
		.empty = "",
		.path = {"/dev/hvgr0", "/dev/mali0", "/dev/kgsl-3d0", "/dev/dri/renderD128"},
	},
};

int isolate_device_index(const char *path)
{
	for (int i = 0; i < ISOLATE_DEVICES; i++)
		if (!z_strncmp(path, g_isolate_page.table.path[i], ISOLATE_PATH_MAX))
			return i;
	return -1;
}
_Static_assert(ISOLATE_DEVICES == CONFIG_ISOLATE_DEVICES, "device table size");
