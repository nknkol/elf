#ifndef STUB_H
#define STUB_H

#include <stdint.h>

/* Stub layout constants */
#define STUB_DATA_OFFSET 0x30
#define STUB_SIZE        80

/* Emit a syscall hook stub at the provided slot. Returns the entry address. */
uintptr_t stub_emit(void *slot, uintptr_t payload_addr, uintptr_t return_addr);

#endif
