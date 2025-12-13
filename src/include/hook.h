#ifndef HOOK_H
#define HOOK_H

#include <stddef.h>
#include <stdint.h>

void *load_raw_payload(const char *path, size_t *size_out);
int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size);
void set_hook_range(int min, int max);
void set_hook_log_level(int level);

#endif
