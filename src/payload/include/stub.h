#ifndef STUB_H
#define STUB_H

#if defined(PROOT_PATH) && defined(FD_EXPERIMENT)
#define PAYLOAD_ABI_VERSION 5
#elif defined(PROOT_PATH)
#define PAYLOAD_ABI_VERSION 3
#else
#define PAYLOAD_ABI_VERSION 2
#endif
#define PAYLOAD_CLONE_ENTRY_OFFSET 16
#define STUB_CLONE_RESUME_OFFSET 100
#ifndef __ASSEMBLER__
#include <stdint.h>
#endif

/* Stub layout constants */
#define STUB_DATA_OFFSET 0xa0
#define STUB_SIZE        0xc0

/* Emit a syscall hook stub at the provided slot. Returns the entry address. */
#ifndef __ASSEMBLER__
uintptr_t stub_emit(void *slot, uintptr_t payload_addr, uintptr_t return_addr);
#endif

#endif
