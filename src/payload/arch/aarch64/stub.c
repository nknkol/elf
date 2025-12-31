#include <stddef.h>
#include "stub.h"

static uint32_t make_branch(uintptr_t src, uintptr_t dest)
{
	int64_t offset = (int64_t)dest - (int64_t)src;
	if (offset < -134217728 || offset > 134217727)
		return 0;
	if (offset & 0x3)
		return 0;
	uint32_t imm26 = (uint32_t)((offset >> 2) & 0x03ffffff);
	return 0x14000000 | imm26;
}

#define STUB_TLS_SLOTS 1024

struct stub_tls_slot {
	uint64_t tp;
	uint64_t x16;
	uint64_t x17;
	uint64_t x30;
};

static struct stub_tls_slot g_stub_tls_slots[STUB_TLS_SLOTS];

static uintptr_t stub_tls_base(void)
{
	return (uintptr_t)g_stub_tls_slots;
}

/* Compact stub with BTI landing pad; data starts at STUB_DATA_OFFSET (0xa0). */
uintptr_t stub_emit(void *slot, uintptr_t payload_addr, uintptr_t return_addr)
{
	static const uint32_t tmpl[] = {
		0xd503245f, /* bti c */
		0xf1022d1f, /* cmp x8, #0x8b (SYS_rt_sigreturn) */
		0x54000360, /* b.eq 0x74 (sigreturn path) */
		0xd53bd049, /* mrs x9, tpidr_el0 */
		0x1000048a, /* adr x10, #0xa0 (data) */
		0xf940094a, /* ldr x10, [x10, #16] (tls base) */
		0xd344fd2b, /* lsr x11, x9, #4 */
		0x9240256b, /* and x11, x11, #0x3ff */
		0xd37be96b, /* lsl x11, x11, #5 */
		0x8b0b014a, /* add x10, x10, x11 */
		0xf9000149, /* str x9, [x10] */
		0xf9000550, /* str x16, [x10, #8] */
		0xf9000951, /* str x17, [x10, #16] */
		0xf9000d5e, /* str x30, [x10, #24] */
		0x10000350, /* adr x16, #0xa0 (data) */
		0xf9400211, /* ldr x17, [x16, #0] */
		0xd63f0220, /* blr x17 */
		0xd503249f, /* bti j (return target for BTI: ret is a jump) */
		0xd53bd049, /* mrs x9, tpidr_el0 */
		0x100002aa, /* adr x10, #0xa0 (data) */
		0xf940094a, /* ldr x10, [x10, #16] (tls base) */
		0xd344fd2b, /* lsr x11, x9, #4 */
		0x9240256b, /* and x11, x11, #0x3ff */
		0xd37be96b, /* lsl x11, x11, #5 */
		0x8b0b014a, /* add x10, x10, x11 */
		0xf9400550, /* ldr x16, [x10, #8] */
		0xf9400951, /* ldr x17, [x10, #16] */
		0xf9400d5e, /* ldr x30, [x10, #24] */
		0x14000000, /* b <return_addr> (patched below) */
		0xd4000001, /* svc #0 (sigreturn path) */
		0x14000000, /* b <return_addr> (patched below) */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
	};

	uint32_t *code = (uint32_t *)slot;
	for (size_t i = 0; i < sizeof(tmpl) / sizeof(tmpl[0]); i++)
		code[i] = tmpl[i];

	uint32_t branch = make_branch((uintptr_t)slot + 28 * 4, return_addr);
	if (branch)
		code[28] = branch;
	branch = make_branch((uintptr_t)slot + 30 * 4, return_addr);
	if (branch)
		code[30] = branch;

	uint64_t *data = (uint64_t *)((uintptr_t)slot + STUB_DATA_OFFSET);
	data[0] = (uint64_t)payload_addr;
	data[1] = (uint64_t)return_addr;
	data[2] = (uint64_t)stub_tls_base();

	return (uintptr_t)slot;
}
