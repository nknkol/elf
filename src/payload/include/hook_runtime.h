#ifndef PAYLOAD_HOOK_RUNTIME_H
#define PAYLOAD_HOOK_RUNTIME_H

#include <stddef.h>

/* Install payload stub on SVC instructions within [target_base, target_base+size). */
int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size);

#endif /* PAYLOAD_HOOK_RUNTIME_H */
