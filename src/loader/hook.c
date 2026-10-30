/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Syscall hooking of the initial images (stub_island.h): the loader side
 * of the island primitives, and the islands to protect later. */
#include <asm/unistd.h>
#include "loader.h"
#include "stub_island.h"

long island_mmap(uintptr_t addr, size_t len, int prot, int flags)
{
	return z_syscall(__NR_mmap, addr, len, prot, flags, -1, 0);
}
long island_munmap(uintptr_t addr, size_t len)
{
	return z_syscall(__NR_munmap, addr, len);
}
long island_mprotect(uintptr_t addr, size_t len, int prot)
{
	return z_syscall(__NR_mprotect, addr, len, prot);
}
long island_pread(int fd, void *buf, size_t len, long offset)
{
	return z_syscall(__NR_pread64, fd, buf, len, offset);
}

static int g_section_scan;
void hook_set_section_scan(int enabled) { g_section_scan = enabled; }

/* Islands made for the initial images; copied into the payload config. */
uint64_t g_loader_islands[64][2];
unsigned g_loader_island_count;
int island_note(uintptr_t base, size_t len)
{
	/* The payload config holds 63 islands next to the loader image. */
	if (g_loader_island_count >= 63)
		return -1;
	g_loader_islands[g_loader_island_count][0] = base;
	g_loader_islands[g_loader_island_count][1] = base + len;
	g_loader_island_count++;
	return 0;
}

long install_hook_file(void *target_base, size_t target_size, void *payload_entry, int prot,
		       int fd, unsigned long file_off)
{
	if (!payload_entry || !target_base || !target_size)
		return 0;
	struct island_code code[ISLAND_CODE_MAX];
	/* Section headers do not limit control flow: only with the seccomp
	 * backstop catching anything skipped may scanning trust them. */
	int ranges = g_section_scan ? island_code_ranges(fd, file_off, target_size, code) : 0;
	/* Nothing runs this code yet: patch through a read-write view. */
	long rc = island_hook_code((uintptr_t)target_base, target_size, (uintptr_t)payload_entry,
				   PROT_READ | PROT_WRITE, prot, code, ranges);
	if (rc < 0)
		z_printf("[loader] cannot cover syscalls in %p (+%lu): %ld\n",
			 target_base, (unsigned long)target_size, rc);
	return rc;
}
