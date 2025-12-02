#include <stddef.h>
#include <stdint.h>

/* Flush instruction/data cache for the given region (AArch64). */
void arch_flush_cache(void *addr, size_t len)
{
	uintptr_t start = (uintptr_t)addr;
	uintptr_t end = start + len;
	uintptr_t p;

	for (p = start; p < end; p += 4)
		__asm__ volatile ("dc cvau, %0" : : "r"(p) : "memory");
	if (p < end + 4)
		__asm__ volatile ("dc cvau, %0" : : "r"(end - 1) : "memory");
	__asm__ volatile ("dsb ish");

	for (p = start; p < end; p += 4)
		__asm__ volatile ("ic ivau, %0" : : "r"(p) : "memory");
	if (p < end + 4)
		__asm__ volatile ("ic ivau, %0" : : "r"(end - 1) : "memory");
	__asm__ volatile ("dsb ish");
	__asm__ volatile ("isb");
}
