/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_VM_WRITE_GUARD_H
#define ELF_VM_WRITE_GUARD_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#define VM_WRITE_REGIONS 128
struct vm_write_region { uintptr_t begin, end; };
/* Sorted, disjoint, coalesced half-open ranges admitted by the runtime.
 * No VFS, allocation, OS probing, or FD lifetime dependency. Caller serializes
 * access and supplies page-rounded ranges; failed edits leave input intact. */
struct vm_write_guard {
    size_t count;
    struct vm_write_region regions[VM_WRITE_REGIONS];
};
int vm_write_add(struct vm_write_guard *, uintptr_t, uintptr_t);
int vm_write_remove(struct vm_write_guard *, uintptr_t, uintptr_t);
bool vm_write_covers(const struct vm_write_guard *, uintptr_t, uintptr_t);
#endif
