/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Compiler-generated calls in a loader linked without libc. volatile keeps
 * the compiler from turning these loops back into calls to themselves. */
#include <stddef.h>

void *memcpy(void *d, const void *s, size_t n)
{
	volatile unsigned char *a = d;
	const volatile unsigned char *b = s;
	for (size_t i = 0; i < n; i++)
		a[i] = b[i];
	return d;
}

void *memset(void *d, int c, size_t n)
{
	volatile unsigned char *a = d;
	for (size_t i = 0; i < n; i++)
		a[i] = (unsigned char)c;
	return d;
}
