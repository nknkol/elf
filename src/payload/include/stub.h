#ifndef STUB_H
#define STUB_H

#include "elf_abi.h"
#define PAYLOAD_CLONE_ENTRY_OFFSET 16
#define STUB_CLONE_RESUME_OFFSET 100
/* The child's continuation: its x16/x17 sit CLONE_CHILD_KEEP bytes below
 * the new SP, so the bytes just below it stay as the program left them
 * (Go's runtime.clone passes m, g, fn and a magic word there), as below
 * STUB_RED_ZONE for every other call. */
#define STUB_CLONE_CHILD_RESUME_OFFSET 112
#define CLONE_CHILD_KEEP 64
/* Bytes below the guest's SP a stub leaves as they are: its own frame (the
 * saved x16/x17/x30) sits under them. Without signals nothing else writes
 * below SP, and programs count on it: Go's clone child makes a call before
 * reading the m, g and fn its parent put just below the new stack. */
#define STUB_RED_ZONE 64
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
