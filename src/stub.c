#include <stddef.h>
#include "stub.h"

/* Compact stub with BTI landing pad; data starts at STUB_DATA_OFFSET */
uintptr_t stub_emit(void *slot, uintptr_t payload_addr, uintptr_t return_addr)
{
	static const uint32_t tmpl[] = {
		0xd503245f, /* bti c */
		0x10000170, /* adr x16, #0x2c (data) */
		0xf9000a1e, /* str x30, [x16, #16] */
		0xf9400211, /* ldr x17, [x16, #0] */
		0xd63f0220, /* blr x17 */
		0x100000f0, /* adr x16, #0x1c (data) */
		0xf9400a1e, /* ldr x30, [x16, #16] */
		0xf9400611, /* ldr x17, [x16, #8] */
		0xd61f0220, /* br x17 */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
	};

	uint32_t *code = (uint32_t *)slot;
	for (size_t i = 0; i < sizeof(tmpl) / sizeof(tmpl[0]); i++)
		code[i] = tmpl[i];

	uint64_t *data = (uint64_t *)((uintptr_t)slot + STUB_DATA_OFFSET);
	data[0] = (uint64_t)payload_addr;
	data[1] = (uint64_t)return_addr;
	data[2] = 0;

	return (uintptr_t)slot;
}
