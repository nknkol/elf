/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Signal handlers of the loader: the kernel sigaction ABI, and the crash
 * dump installed only when logging is enabled (diagnostics; the guest's own
 * handlers replace it). */
#include <asm/unistd.h>
#include <ucontext.h>
#include "loader.h"

typedef struct {
	signal_handler_t handler;
	unsigned long flags;
	void (*restorer)(void);
	unsigned long mask; /* AArch64 kernel sigset: one word */
} k_sigaction_t;

int signal_install(int sig, signal_handler_t handler, unsigned long flags)
{
	k_sigaction_t sa = {handler, flags, 0, 0};
	return z_syscall(__NR_rt_sigaction, sig, handler ? &sa : NULL, NULL, sizeof(sa.mask)) < 0 ? -1 : 0;
}

/* Restore the default action and die of the signal, as the program would
 * natively. */
void die_of_signal(int sig)
{
	k_sigaction_t dfl = {0, 0, 0, 0};
	z_syscall(__NR_rt_sigaction, sig, &dfl, NULL, sizeof(dfl.mask));
	z_syscall(__NR_tgkill, z_syscall(__NR_getpid), z_syscall(__NR_gettid), sig);
}

static volatile sig_atomic_t g_dumping;

static void dbg_write_all(const char *buf, size_t len)
{
	while (len) {
		ssize_t n = z_write(2, buf, len);
		if (n <= 0)
			break;
		buf += n;
		len -= (size_t)n;
	}
}

static void dbg_write_cstr(const char *s)
{
	dbg_write_all(s, z_strlen(s));
}

static size_t dbg_append_str(char *buf, size_t cap, size_t pos, const char *s)
{
	if (!buf || !s || cap == 0)
		return pos;
	while (pos + 1 < cap && *s) {
		buf[pos++] = *s++;
	}
	return pos;
}

static size_t dbg_append_uint(char *buf, size_t cap, size_t pos, unsigned long v)
{
	char tmp[32];
	size_t tpos = 0;
	if (v == 0) {
		tmp[tpos++] = '0';
	} else {
		while (v > 0 && tpos < sizeof(tmp)) {
			tmp[tpos++] = (char)('0' + (v % 10));
			v /= 10;
		}
	}
	while (tpos > 0 && pos + 1 < cap)
		buf[pos++] = tmp[--tpos];
	return pos;
}

static size_t dbg_append_hex64(char *buf, size_t cap, size_t pos, unsigned long v)
{
	static const char hex[] = "0123456789abcdef";
	if (!buf || cap == 0)
		return pos;
	if (pos + 2 < cap) {
		buf[pos++] = '0';
		buf[pos++] = 'x';
	}
	for (int i = 0; i < 16 && pos + 1 < cap; i++) {
		int shift = 60 - (i * 4);
		buf[pos++] = hex[(v >> shift) & 0xf];
	}
	return pos;
}

static size_t dbg_append_hex8(char *buf, size_t cap, size_t pos, unsigned int v)
{
	static const char hex[] = "0123456789abcdef";
	if (!buf || cap == 0)
		return pos;
	if (pos + 2 < cap) {
		buf[pos++] = hex[(v >> 4) & 0xf];
		buf[pos++] = hex[v & 0xf];
	}
	return pos;
}

static void dbg_dump_regs(const ucontext_t *uc)
{
	if (!uc)
		return;
	const unsigned long *regs = uc->uc_mcontext.regs;
	char line[256];
	size_t pos = 0;

	dbg_write_cstr("[Debugger] ARM64 register dump:\n");
	for (int i = 0; i < 31; i++) {
		line[pos++] = 'x';
		pos = dbg_append_uint(line, sizeof(line), pos, (unsigned long)i);
		if (pos + 1 < sizeof(line))
			line[pos++] = '=';
		pos = dbg_append_hex64(line, sizeof(line), pos, regs[i]);
		if ((i % 4) == 3 || i == 30) {
			if (pos + 1 < sizeof(line))
				line[pos++] = '\n';
			dbg_write_all(line, pos);
			pos = 0;
		} else if (pos + 1 < sizeof(line)) {
			line[pos++] = ' ';
		} else {
			dbg_write_all(line, pos);
			pos = 0;
		}
	}

	char meta[160];
	size_t p = 0;
	p = dbg_append_str(meta, sizeof(meta), p, "SP=");
	p = dbg_append_hex64(meta, sizeof(meta), p, uc->uc_mcontext.sp);
	p = dbg_append_str(meta, sizeof(meta), p, " PC=");
	p = dbg_append_hex64(meta, sizeof(meta), p, uc->uc_mcontext.pc);
	p = dbg_append_str(meta, sizeof(meta), p, " PSTATE=");
	p = dbg_append_hex64(meta, sizeof(meta), p, uc->uc_mcontext.pstate);
	if (p + 1 < sizeof(meta))
		meta[p++] = '\n';
	dbg_write_all(meta, p);

	char fault[96];
	p = 0;
	p = dbg_append_str(fault, sizeof(fault), p, "Fault address=");
	p = dbg_append_hex64(fault, sizeof(fault), p, uc->uc_mcontext.fault_address);
	if (p + 1 < sizeof(fault))
		fault[p++] = '\n';
	dbg_write_all(fault, p);
}

static void dbg_dump_stack(const ucontext_t *uc)
{
	if (!uc)
		return;
	const unsigned long sp = uc->uc_mcontext.sp;
	const unsigned long *ptr = (const unsigned long *)sp;
	if (!ptr) {
		dbg_write_cstr("[Debugger] Stack pointer is NULL\n");
		return;
	}

	dbg_write_cstr("[Debugger] Stack snapshot (top 16 qwords):\n");
	for (int i = 0; i < 16; i++) {
		char line[192];
		size_t pos = 0;
		pos = dbg_append_str(line, sizeof(line), pos, "  [");
		pos = dbg_append_uint(line, sizeof(line), pos, (unsigned long)i);
		pos = dbg_append_str(line, sizeof(line), pos, "] ");
		pos = dbg_append_hex64(line, sizeof(line), pos, (unsigned long)(ptr + i));
		pos = dbg_append_str(line, sizeof(line), pos, ": ");
		unsigned long val = ptr[i];
		pos = dbg_append_hex64(line, sizeof(line), pos, val);
		if (pos + 1 < sizeof(line))
			line[pos++] = '\n';
		dbg_write_all(line, pos);
	}
}

static void dbg_dump_bytes(const char *tag, const unsigned char *addr, size_t len)
{
	if (!addr || len == 0)
		return;
	if (tag)
		dbg_write_cstr(tag);
	size_t per_line = 16;
	for (size_t off = 0; off < len; off += per_line) {
		char line[256];
		size_t pos = 0;
		pos = dbg_append_str(line, sizeof(line), pos, "  ");
		pos = dbg_append_hex64(line, sizeof(line), pos, (unsigned long)(addr + off));
		pos = dbg_append_str(line, sizeof(line), pos, ": ");
		size_t chunk = per_line;
		if (off + chunk > len)
			chunk = len - off;
		for (size_t i = 0; i < chunk; i++) {
			pos = dbg_append_hex8(line, sizeof(line), pos, addr[off + i]);
			if (pos + 1 < sizeof(line))
				line[pos++] = ' ';
		}
		if (pos + 1 < sizeof(line))
			line[pos++] = '\n';
		dbg_write_all(line, pos);
	}
}

static int dbg_parse_hex64(const char *s, size_t len, unsigned long *out, size_t *consumed)
{
	unsigned long v = 0;
	size_t i = 0;
	while (i < len) {
		char c = s[i];
		unsigned int d;
		if (c >= '0' && c <= '9')
			d = (unsigned int)(c - '0');
		else if (c >= 'a' && c <= 'f')
			d = (unsigned int)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			d = (unsigned int)(c - 'A' + 10);
		else
			break;
		v = (v << 4) | d;
		i++;
	}
	if (i == 0)
		return 0;
	*out = v;
	*consumed = i;
	return 1;
}

static void dbg_dump_maps_for_addr(const char *tag, unsigned long addr)
{
	int fd = z_open("/proc/self/maps", O_RDONLY);
	if (fd < 0)
		return;

	char buf[1024];
	char line[512];
	size_t line_len = 0;
	ssize_t n;

	while ((n = z_read(fd, buf, sizeof(buf))) > 0) {
		for (ssize_t i = 0; i < n; i++) {
			char c = buf[i];
			if (line_len + 1 < sizeof(line))
				line[line_len++] = c;
			if (c == '\n') {
				unsigned long start = 0, end = 0;
				size_t used = 0, used2 = 0;
				if (dbg_parse_hex64(line, line_len, &start, &used) &&
				    used + 1 < line_len && line[used] == '-' &&
				    dbg_parse_hex64(line + used + 1, line_len - used - 1, &end, &used2)) {
					if (addr >= start && addr < end) {
						if (tag)
							dbg_write_cstr(tag);
						dbg_write_all(line, line_len);
						z_close(fd);
						return;
					}
				}
				line_len = 0;
			}
		}
	}

	if (line_len > 0) {
		unsigned long start = 0, end = 0;
		size_t used = 0, used2 = 0;
		if (dbg_parse_hex64(line, line_len, &start, &used) &&
		    used + 1 < line_len && line[used] == '-' &&
		    dbg_parse_hex64(line + used + 1, line_len - used - 1, &end, &used2)) {
			if (addr >= start && addr < end) {
				if (tag)
					dbg_write_cstr(tag);
				dbg_write_all(line, line_len);
			}
		}
	}

	z_close(fd);
}

static void loader_sigsegv_handler(int sig, siginfo_t *si, void *ucontext)
{
	if (g_dumping)
		die_of_signal(sig);
	g_dumping = 1;

	dbg_write_cstr("[Debugger] Caught signal ");
	char sigbuf[32];
	size_t spos = 0;
	spos = dbg_append_uint(sigbuf, sizeof(sigbuf), spos, (unsigned long)sig);
	if (spos + 1 < sizeof(sigbuf))
		sigbuf[spos++] = '\n';
	dbg_write_all(sigbuf, spos);
	if (si) {
		char line[128];
		size_t pos = 0;
		pos = dbg_append_str(line, sizeof(line), pos, "  si_code=");
		pos = dbg_append_uint(line, sizeof(line), pos, (unsigned long)si->si_code);
		pos = dbg_append_str(line, sizeof(line), pos, " si_addr=");
		pos = dbg_append_hex64(line, sizeof(line), pos, (unsigned long)si->si_addr);
		if (pos + 1 < sizeof(line))
			line[pos++] = '\n';
		dbg_write_all(line, pos);
	}

	dbg_dump_regs((const ucontext_t *)ucontext);
	dbg_dump_stack((const ucontext_t *)ucontext);

	const ucontext_t *uc = (const ucontext_t *)ucontext;
	const unsigned char *pc_bytes = (const unsigned char *)uc->uc_mcontext.pc;
	if (pc_bytes) {
		dbg_dump_maps_for_addr("[Debugger] PC map: ", (unsigned long)pc_bytes);
		unsigned long page = TRUNC_PG((unsigned long)pc_bytes);
		if (z_mprotect((void *)page, PAGE_SIZE, PROT_READ | PROT_EXEC) < 0) {
			char msg[128];
			size_t pos = 0;
			pos = dbg_append_str(msg, sizeof(msg), pos, "[Debugger] mprotect PC page failed: ");
			pos = dbg_append_uint(msg, sizeof(msg), pos, (unsigned long)z_errno);
			if (pos + 1 < sizeof(msg))
				msg[pos++] = '\n';
			dbg_write_all(msg, pos);
		} else {
			unsigned long base = (unsigned long)pc_bytes & ~(unsigned long)0xf;
			dbg_dump_bytes("[Debugger] Bytes near PC:\n", (const unsigned char *)base, 32);
		}
	}
	if (si && si->si_addr) {
		dbg_dump_maps_for_addr("[Debugger] Fault map: ", (unsigned long)si->si_addr);
		const unsigned char *fa = (const unsigned char *)si->si_addr;
		unsigned long page = TRUNC_PG((unsigned long)fa);
		if (z_mprotect((void *)page, PAGE_SIZE, PROT_READ | PROT_EXEC) == 0) {
			unsigned long base = (unsigned long)fa & ~(unsigned long)0xf;
			dbg_dump_bytes("[Debugger] Bytes near fault addr:\n", (const unsigned char *)base, 32);
		}
	}

	die_of_signal(sig);
}

void debugger_install(void)
{
	static unsigned char stack[SIGSTKSZ];
	stack_t ss = {stack, 0, sizeof(stack)};
	if (z_syscall(__NR_sigaltstack, &ss, NULL) < 0) {
		z_printf("[loader] crash dump: no alternate stack\n");
		return;
	}
	static const int sigs[] = {SIGSEGV, SIGBUS, SIGILL};
	for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
		if (signal_install(sigs[i], loader_sigsegv_handler, SA_SIGINFO | SA_ONSTACK) < 0)
			z_printf("[loader] crash dump: cannot handle signal %d\n", sigs[i]);
}

