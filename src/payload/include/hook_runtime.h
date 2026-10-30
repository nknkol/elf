#ifndef PAYLOAD_HOOK_RUNTIME_H
#define PAYLOAD_HOOK_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

/* Install payload stub on SVC instructions within [target_base, target_base+size). */
int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size);
/* Same, restoring prot; negative when a site could not be covered (then
 * nothing is patched and the caller must not leave the range executable). */
long install_hook_prot(void *target_base, size_t target_size, void *payload_entry, int prot);
/* For a range copied from fd at file_off: only code sections are scanned. */
long install_hook_file(void *target_base, size_t target_size, void *payload_entry, int prot,
                       int fd, unsigned long file_off);
/* Whether [addr, addr + len) touches loader, payload or stub-island memory. */
int hook_protected_overlap(uintptr_t addr, size_t len);

#endif /* PAYLOAD_HOOK_RUNTIME_H */
