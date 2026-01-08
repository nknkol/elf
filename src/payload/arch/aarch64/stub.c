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

/* Compact stub with BTI landing pad; data starts at STUB_DATA_OFFSET (0xa0). */
uintptr_t stub_emit(void *slot, uintptr_t payload_addr, uintptr_t return_addr)
{
	static const uint32_t tmpl[] = {
		0xd503245f, /* bti c */
		0xf1022d1f, /* cmp x8, #0x8b (SYS_rt_sigreturn) */
		0x540001c0, /* b.eq sigreturn */
		0xf103711f, /* cmp x8, #0xdc (SYS_clone) */
		0x54000180, /* b.eq passthrough */
		0xd10083ff, /* sub sp, sp, #0x20 */
		0xa90047f0, /* stp x16, x17, [sp] */
		0xf9000bfe, /* str x30, [sp, #0x10] */
		0x10000410, /* adr x16, #0xa0 (data) */
		0xf9400211, /* ldr x17, [x16, #0] */
		0xd63f0220, /* blr x17 */
		0xd503249f, /* bti j (return target for BTI: ret is a jump) */
		0xf9400bfe, /* ldr x30, [sp, #0x10] */
		0xa94047f0, /* ldp x16, x17, [sp] */
		0x910083ff, /* add sp, sp, #0x20 */
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
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
		0xd503201f, /* nop */
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

	uint32_t branch = make_branch((uintptr_t)slot + 15 * 4, return_addr);
	if (branch)
		code[15] = branch;
	branch = make_branch((uintptr_t)slot + 17 * 4, return_addr);
	if (branch)
		code[17] = branch;

	uint64_t *data = (uint64_t *)((uintptr_t)slot + STUB_DATA_OFFSET);
	data[0] = (uint64_t)payload_addr;
	data[1] = (uint64_t)return_addr;
	data[2] = 0;

	return (uintptr_t)slot;
}
