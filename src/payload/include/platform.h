/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PLATFORM_H
#define PLATFORM_H
#include <stddef.h>
/* uname sysname is "HarmonyOS" (cached). */
int platform_is_harmonyos(void);
/* mprotect that may add PROT_EXEC to anonymous memory (HarmonyOS needs its
 * JIT window around it). Returns 0 or -errno. */
long platform_mprotect_exec(unsigned long addr, size_t len, int prot);
#endif
