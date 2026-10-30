#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <syscall.h>

#ifdef sa_handler
#undef sa_handler
#endif
#ifdef sa_sigaction
#undef sa_sigaction
#endif
#ifdef sa_restorer
#undef sa_restorer
#endif

#include "z_asm.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include "z_elf.h"
#include "arch.h"
#include "hook.h"
#include "config.h"
#include "stub.h"

#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0x20000
#endif

#define PAGE_SIZE	4096
#define ALIGN		(PAGE_SIZE - 1)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR	((unsigned long)-1)
#define SYMLINK_MAX_DEPTH 4

#ifndef __NR_uname
#if defined(__aarch64__)
#define __NR_uname 160
#elif defined(__x86_64__)
#define __NR_uname 63
#elif defined(__i386__)
#define __NR_uname 122
#else
#define __NR_uname 63
#endif
#endif

#define UTSNAME_LEN 65
typedef struct {
	char sysname[UTSNAME_LEN];
	char nodename[UTSNAME_LEN];
	char release[UTSNAME_LEN];
	char version[UTSNAME_LEN];
	char machine[UTSNAME_LEN];
	char domainname[UTSNAME_LEN];
} k_utsname_t;

static int g_hook_min_default = 0;
static int g_hook_max_default = 0x7fffffff;
static int g_hook_min_interp = 0;
static int g_hook_max_interp = 0x7fffffff;
static unsigned long g_loader_version = 0;

/* Embedded debugger: dump guest state on SIGSEGV using a safe alt stack. */
static unsigned char g_sigsegv_stack[SIGSTKSZ];
static stack_t g_sigsegv_stack_cfg;
static volatile sig_atomic_t g_sigsegv_handling = 0;

static int install_guest_debugger(void);

/* Kernel ABI sigset/sigaction (avoid libc layout differences). */
typedef struct {
	unsigned long sig[1]; /* AArch64 kernel expects 1-word sigset */
} k_sigset_t;

typedef void (*k_sigaction_handler_t)(int, siginfo_t *, void *);
typedef struct {
	k_sigaction_handler_t sa_handler;
	unsigned long sa_flags;
	void (*sa_restorer)(void);
	k_sigset_t sa_mask;
} k_sigaction_t;

static k_sigaction_t g_prev_sigsegv;

#ifndef __NR_rt_sigaction
#define __NR_rt_sigaction 13
#endif
#ifndef __NR_sigaltstack
#define __NR_sigaltstack 132
#endif

static long dbg_syscall_check(long rc)
{
	if (rc < 0 && rc > -4096) {
		z_errno = (int)-rc;
		return -1;
	}
	return rc;
}

static int dbg_rt_sigaction(int signum, const k_sigaction_t *act,
			    k_sigaction_t *oldact)
{
	return (int)dbg_syscall_check(z_syscall(__NR_rt_sigaction,
						signum, act, oldact,
						sizeof(k_sigset_t), 0, 0));
}

static int dbg_sigaltstack(const stack_t *ss, stack_t *old)
{
	return (int)dbg_syscall_check(z_syscall(__NR_sigaltstack,
						ss, old, 0, 0, 0, 0));
}

static void dbg_sigemptyset(k_sigset_t *set)
{
	if (set)
		z_memset(set, 0, sizeof(*set));
}

static size_t dbg_strlen(const char *s)
{
	size_t n = 0;
	while (s && s[n])
		n++;
	return n;
}

static void dbg_write_all(const char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = z_write(2, buf + off, len - off);
		if (n <= 0)
			break;
		off += (size_t)n;
	}
}

static void dbg_write_cstr(const char *s)
{
	if (!s)
		return;
	dbg_write_all(s, dbg_strlen(s));
}

static unsigned long generate_loader_version(void)
{
	/* 低成本伪随机：混合几个静态符号地址，再做几轮搅动 */
	unsigned long v = (unsigned long)&g_loader_version;
	v ^= (unsigned long)&g_hook_min_default << 7;
	v ^= (unsigned long)&install_hook << 13;
	v ^= (unsigned long)&install_guest_debugger << 21;

	/* xorshift64* */
	v ^= v >> 12;
	v ^= v << 25;
	v ^= v >> 27;
	v *= 0x2545F4914F6CDD1Dull;
	if (v == 0)
		v = 0x9e3779b97f4a7c15ull; /* 避免输出 0 */
	return v;
}

static int is_harmonyos(void)
{
	static int cached = -1;
	if (cached >= 0)
		return cached;

	k_utsname_t u;
	long rc = z_syscall(__NR_uname, &u, 0, 0, 0, 0, 0);
	if (rc < 0) {
		cached = 0;
		return cached;
	}

	if (z_strncmp(u.sysname, "HarmonyOS", 9) == 0 && u.sysname[9] == '\0')
		cached = 1;
	else
		cached = 0;
	return cached;
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
#if defined(__aarch64__)
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
#else
	(void)uc;
	dbg_write_cstr("[Debugger] Register dump not implemented for this arch\n");
#endif
}

static void dbg_dump_stack(const ucontext_t *uc)
{
#if defined(__aarch64__)
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
#else
	(void)uc;
	dbg_write_cstr("[Debugger] Stack dump not implemented for this arch\n");
#endif
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
	if (g_sigsegv_handling) {
		dbg_write_cstr("[Debugger] Recursive SIGSEGV inside handler, exiting\n");
		z_exit(128 + SIGSEGV);
	}
	g_sigsegv_handling = 1;

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

#if defined(__aarch64__)
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
#endif

	z_exit(128 + SIGSEGV);
}

static int install_guest_debugger(void)
{
	z_printf("[Debugger] Installing SIGSEGV handler...\n");
	g_sigsegv_stack_cfg.ss_sp = g_sigsegv_stack;
	g_sigsegv_stack_cfg.ss_size = sizeof(g_sigsegv_stack);
	g_sigsegv_stack_cfg.ss_flags = 0;
	if (dbg_sigaltstack(&g_sigsegv_stack_cfg, NULL) < 0) {
		z_fdprintf(2, "[Debugger] sigaltstack failed: %d\n", z_errno);
		return -1;
	}

	k_sigaction_t sa;
	z_memset(&sa, 0, sizeof(sa));
	sa.sa_handler = (k_sigaction_handler_t)loader_sigsegv_handler;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	dbg_sigemptyset(&sa.sa_mask);

	int sigs[] = { SIGSEGV, SIGBUS, SIGILL };
	for (unsigned i = 0; i < sizeof(sigs)/sizeof(sigs[0]); i++) {
		int rc = dbg_rt_sigaction(sigs[i], &sa, &g_prev_sigsegv);
		if (rc < 0) {
			z_fdprintf(2, "[Debugger] sigaction(%d) failed: %d\n", sigs[i], z_errno);
			return -1;
		}
	}
	z_printf("[Debugger] SIGSEGV handler installed (altstack=%p size=%lu)\n",
		 g_sigsegv_stack_cfg.ss_sp, (unsigned long)g_sigsegv_stack_cfg.ss_size);
	return 0;
}

#if defined(PROOT_PATH) && defined(__aarch64__)
/* --seccomp-backstop: a seccomp filter traps every syscall that does not
 * come from the loader image or the payload (both at fixed addresses, so
 * the filter, which survives exec, stays valid in every descendant). The
 * SIGSYS handler forwards the trapped call into the payload exactly as a
 * stub would, so unhooked svc (JIT code, unreachable sites, the vDSO
 * fallback) still gets guest semantics. rt_sigreturn, exit, exit_group,
 * restart_syscall and clone are allowed by number: they take no paths and
 * clone cannot run inside a signal handler. */
#define PAYLOAD_FIXED_BASE 0x3f80000000ul
static unsigned long g_payload_lo, g_payload_hi, g_payload_entry;
extern char __ehdr_start[], _end[];

static long backstop_call(unsigned long entry, const unsigned long *r)
{
	register long x0 __asm__("x0") = (long)r[0];
	register long x1 __asm__("x1") = (long)r[1], x2 __asm__("x2") = (long)r[2];
	register long x3 __asm__("x3") = (long)r[3], x4 __asm__("x4") = (long)r[4];
	register long x5 __asm__("x5") = (long)r[5];
	register long x8 __asm__("x8") = (long)(unsigned)r[8]; /* The kernel's int. */
	register unsigned long x17 __asm__("x17") = entry;
	/* The payload entry restores every register except x0 (and the x16,
	 * x17 and x30 a stub saves itself). */
	__asm__ volatile("blr x17"
			 : "+r"(x0)
			 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8), "r"(x17)
			 : "x16", "x30", "memory", "cc");
	return x0;
}

/* Our TRAP action's data, delivered in si_errno: the host sandbox's own
 * filter traps some calls too, and those must keep their native effect. */
#define BACKSTOP_TRAP_DATA 0x0e1f

static void loader_sigsys_handler(int sig, siginfo_t *si, void *ucontext)
{
	ucontext_t *uc = (ucontext_t *)ucontext;
	if (!si || si->si_code != 1 /* SYS_SECCOMP */ || si->si_errno != BACKSTOP_TRAP_DATA || !uc) {
		/* Not ours: die of SIGSYS as the program would natively. */
		k_sigaction_t dfl;
		z_memset(&dfl, 0, sizeof(dfl));
		dbg_rt_sigaction(sig, &dfl, NULL);
		z_syscall(__NR_tgkill, z_syscall(__NR_getpid), z_syscall(__NR_gettid), sig);
		return;
	}
	unsigned long *regs = (unsigned long *)uc->uc_mcontext.regs;
	regs[0] = (unsigned long)backstop_call(g_payload_entry, regs);
}

static int backstop_handler(void)
{
	k_sigaction_t sa;
	z_memset(&sa, 0, sizeof(sa));
	sa.sa_handler = (k_sigaction_handler_t)loader_sigsys_handler;
	/* NODEFER: a guest handler run from here may itself trap. */
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
	dbg_sigemptyset(&sa.sa_mask);
	return dbg_rt_sigaction(SIGSYS, &sa, NULL);
}

static int backstop_filter(void)
{
	unsigned long ranges[2][2] = {{(unsigned long)__ehdr_start, (unsigned long)_end},
				      {g_payload_lo, g_payload_hi}};
	struct { unsigned short code; unsigned char jt, jf; unsigned int k; } f[32];
	int n = 0;
#define BPF(c, t, e, v) (f[n++] = (typeof(f[0])){(c), (t), (e), (v)})
	/* seccomp_data: nr at 0, arch at 4, instruction_pointer at 8. */
	BPF(0x20, 0, 0, 0); /* ld nr */
	static const unsigned allowed[] = {139, 93, 94, 128, 220, 435};
	for (unsigned i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
		BPF(0x15, 0, 0, allowed[i]); /* jeq -> allow (patched below) */
	int nr_checks = n;
	for (int r = 0; r < 2; r++) {
		if ((ranges[r][0] >> 32) != ((ranges[r][1] - 1) >> 32))
			return -1; /* A range across a 4 GiB boundary: unsupported. */
		BPF(0x20, 0, 0, 12);                                /* ld ip high */
		BPF(0x15, 0, 4, (unsigned)(ranges[r][0] >> 32));    /* jeq hi */
		BPF(0x20, 0, 0, 8);                                 /* ld ip low */
		BPF(0x35, 0, 2, (unsigned)ranges[r][0]);            /* jge lo */
		BPF(0x35, 1, 0, (unsigned)ranges[r][1]);            /* jge hi -> next */
		BPF(0x06, 0, 0, 0x7fff0000u);                       /* ret ALLOW */
	}
	BPF(0x06, 0, 0, 0x00030000u | BACKSTOP_TRAP_DATA);          /* ret TRAP */
	BPF(0x06, 0, 0, 0x7fff0000u);                               /* ret ALLOW */
	for (int i = 1; i < nr_checks; i++)
		f[i].jt = (unsigned char)(n - 1 - (i + 1));
#undef BPF
	struct { unsigned short len; void *filter; } prog = {(unsigned short)n, f};
	if (z_syscall(__NR_prctl, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0) < 0)
		return -1;
	return (int)dbg_syscall_check(z_syscall(__NR_seccomp, 1 /* SET_MODE_FILTER */, 0,
						&prog, 0, 0, 0));
}
#endif

static void z_fini(void)
{
	/* No-op placeholder for atexit style hook */
}

extern unsigned char _binary_tiny_init_tiny_init_start[];
extern unsigned char _binary_tiny_init_tiny_init_end[];
extern unsigned char _binary_payload_payload_bin_start[];
extern unsigned char _binary_payload_payload_bin_end[];
extern unsigned char _binary_shell_dash_start[];
extern unsigned char _binary_shell_dash_end[];

static int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
		e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
	    	e_ident[EI_CLASS] != ELFCLASS ||
		e_ident[EI_VERSION] != EV_CURRENT ||
		(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)) ? 0 : 1;
}

static unsigned long loadelf_anon(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr, void *payload_addr, size_t payload_sz)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;

	typedef struct {
		void *start;
		size_t size;
		int prot;
		unsigned long file_off;
		void *map;
		size_t map_size;
	} exec_seg_t;
	exec_seg_t *exec_segs = z_alloca(ehdr->e_phnum * sizeof(exec_seg_t));
	int exec_cnt = 0;

	minva = (unsigned long)-1;
	maxva = 0;
	
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	base = z_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return -1;
	z_munmap(base, maxva - minva);

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++) {
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		int prot = PFLAGS(iter->p_flags);
		/* Read-only data (rodata, symbol tables) needs no private copy:
		 * code signing only forbids executable file mappings. */
		if (prot == PROT_READ && iter->p_filesz == iter->p_memsz &&
		    (iter->p_offset & ALIGN) == off) {
			p = z_mmap((void *)start, sz, PROT_READ, MAP_FIXED | MAP_PRIVATE, fd,
				   TRUNC_PG(iter->p_offset));
			if (p != (void *)-1)
				continue;
		}

		p = z_mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
		if (p == (void *)-1)
			goto err;
		if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
			goto err;
		if (z_read(fd, p + off, iter->p_filesz) !=
				(ssize_t)iter->p_filesz)
			goto err;

		if ((prot & PROT_EXEC) && payload_addr) {
			exec_segs[exec_cnt].start = (void *)((unsigned long)p + off);
			exec_segs[exec_cnt].size = iter->p_filesz;
			exec_segs[exec_cnt].prot = prot;
			exec_segs[exec_cnt].file_off = iter->p_offset;
			exec_segs[exec_cnt].map = p;
			exec_segs[exec_cnt].map_size = sz;
			exec_cnt++;
			/* Patched while still writable; made executable once below
			 * (each exec transition can resync the whole range). */
			continue;
		}

		if ((prot & PROT_EXEC) && is_harmonyos()) {
			z_prctl(0x6a6974, 0, 0);
		}
		z_mprotect(p, sz, prot);
		if ((prot & PROT_EXEC) && is_harmonyos()) {
			z_prctl(0x6a6974, 0, 1);
		}
	}

	/* Install hooks after mappings complete to keep stub pages intact */
	for (int i = 0; i < exec_cnt; i++) {
		/* Fail closed: a raw svc left unhooked would bypass the payload. */
		if (install_hook_file(exec_segs[i].start, exec_segs[i].size, payload_addr,
				      PROT_READ | PROT_WRITE, fd, exec_segs[i].file_off) < 0)
			z_errx(1, "cannot place syscall stubs within branch range");
		if (is_harmonyos())
			z_prctl(0x6a6974, 0, 0);
		z_mprotect(exec_segs[i].map, exec_segs[i].map_size, exec_segs[i].prot);
		if (is_harmonyos())
			z_prctl(0x6a6974, 0, 1);
	}

	return (unsigned long)base;
err:
	z_munmap(base, maxva - minva);
	return LOAD_ERR;
}

#define Z_PROG		0
#define Z_INTERP	1

#ifndef DT_RELR
#define DT_RELR 36
#endif
/* Payload segments are mapped at base + p_vaddr (first PT_LOAD at 0). */
static int apply_payload_relocations(void *base, const Elf_Ehdr *ehdr, const Elf_Phdr *phdr)
{
	unsigned long b = (unsigned long)base, rela = 0, size = 0, entry = sizeof(Elf64_Rela);
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != PT_DYNAMIC)
			continue;
		for (const Elf64_Dyn *d = (const Elf64_Dyn *)(b + phdr[i].p_vaddr); d->d_tag != DT_NULL; d++) {
			if (d->d_tag == DT_RELA) rela = d->d_un.d_ptr;
			else if (d->d_tag == DT_RELASZ) size = d->d_un.d_val;
			else if (d->d_tag == DT_RELAENT) entry = d->d_un.d_val;
			else if ((d->d_tag == DT_JMPREL || d->d_tag == DT_PLTRELSZ ||
				  d->d_tag == DT_RELR || d->d_tag == DT_REL) && d->d_un.d_val)
				return -1;
		}
	}
	if (!size)
		return 0;
	if (!rela || entry != sizeof(Elf64_Rela) || size % entry)
		return -1;
	for (const Elf64_Rela *r = (const Elf64_Rela *)(b + rela);
	     (unsigned long)r < b + rela + size; r++) {
		if (ELF64_R_TYPE(r->r_info) != R_AARCH64_RELATIVE)
			return -1;
		*(unsigned long *)(b + r->r_offset) = b + r->r_addend;
	}
	return 0;
}

/* Reads payload bytes from the embedded image (blob) or a descriptor. */
static int payload_src_read(int fd, const unsigned char *blob, size_t blob_size,
			    unsigned long offset, void *dst, size_t len)
{
	if (blob) {
		if (offset > blob_size || len > blob_size - offset)
			return -1;
		z_memcpy(dst, blob + offset, len);
		return 0;
	}
	if (z_lseek(fd, (off_t)offset, SEEK_SET) < 0)
		return -1;
	return z_read(fd, dst, len) == (ssize_t)len ? 0 : -1;
}

static void *load_elf_payload_src(int fd, const unsigned char *blob, size_t blob_size,
				  size_t *entry_point_out)
{
	if (fd < 0 && !blob)
		return NULL;

	Elf_Ehdr ehdr;
	if (payload_src_read(fd, blob, blob_size, 0, &ehdr, sizeof(ehdr)) < 0) {
		return NULL;
	}

	if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		return NULL;
	}

	size_t ph_size = ehdr.e_phnum * sizeof(Elf_Phdr);
	Elf_Phdr *phdr = z_alloca(ph_size);
	if (payload_src_read(fd, blob, blob_size, ehdr.e_phoff, phdr, ph_size) < 0) {
		return NULL;
	}

	unsigned long minva = (unsigned long)-1;
	unsigned long maxva = 0;
	for (int i = 0; i < ehdr.e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;
		if (phdr[i].p_vaddr < minva)
			minva = phdr[i].p_vaddr;
		if (phdr[i].p_vaddr + phdr[i].p_memsz > maxva)
			maxva = phdr[i].p_vaddr + phdr[i].p_memsz;
	}
	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);
	size_t total_size = maxva - minva;

	void *base = (void *)-1;
#if defined(PROOT_PATH) && defined(__aarch64__)
	/* A fixed address, identical in every loader-run process (the seccomp
	 * backstop allows the payload's syscalls by address across exec). */
	base = z_mmap((void *)PAYLOAD_FIXED_BASE, total_size, PROT_NONE,
		      MAP_PRIVATE | MAP_ANONYMOUS | 0x100000 /* MAP_FIXED_NOREPLACE */, -1, 0);
	if (base != (void *)-1 && base != (void *)PAYLOAD_FIXED_BASE) {
		z_munmap(base, total_size);
		base = (void *)-1;
	}
#endif
	if (base == (void *)-1)
		base = z_mmap(NULL, total_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == (void *)-1) {
		return NULL;
	}
#if defined(PROOT_PATH) && defined(__aarch64__)
	g_payload_lo = (unsigned long)base;
	g_payload_hi = (unsigned long)base + total_size;
#endif

	for (int i = 0; i < ehdr.e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;

		unsigned long off = phdr[i].p_vaddr & ALIGN;
		unsigned long seg_start = (unsigned long)base + TRUNC_PG(phdr[i].p_vaddr);
		size_t seg_sz = ROUND_PG(phdr[i].p_memsz + off);

		void *p = z_mmap((void *)seg_start, seg_sz, PROT_WRITE,
				 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == (void *)-1) {
			z_munmap(base, total_size);
			return NULL;
		}

		if (payload_src_read(fd, blob, blob_size, phdr[i].p_offset,
				     (void *)((unsigned long)p + off), phdr[i].p_filesz) < 0) {
			z_munmap(base, total_size);
			return NULL;
		}
	}

	/* The payload is position independent; compilers may still emit
	 * RELATIVE relocations (pointer tables, GOT entries). Apply them while
	 * every segment is writable; any other dynamic relocation is refused. */
	if (apply_payload_relocations(base, &ehdr, phdr) < 0) {
		z_munmap(base, total_size);
		return NULL;
	}

	for (int i = 0; i < ehdr.e_phnum; i++) {
		if (phdr[i].p_type != PT_LOAD)
			continue;
		unsigned long off = phdr[i].p_vaddr & ALIGN;
		void *p = (void *)((unsigned long)base + TRUNC_PG(phdr[i].p_vaddr));
		size_t seg_sz = ROUND_PG(phdr[i].p_memsz + off);
		int prot = PFLAGS(phdr[i].p_flags);
		z_mprotect(p, seg_sz, prot);
		if (prot & PROT_EXEC)
			arch_flush_cache(p, seg_sz);
	}

	if (entry_point_out)
		*entry_point_out = (size_t)base + ehdr.e_entry;

	return base;
}

static void *load_elf_payload_fd(int fd, size_t *entry_point_out)
{
	return load_elf_payload_src(fd, NULL, 0, entry_point_out);
}

static void *load_elf_payload_path(const char *path, size_t *entry_point_out)
{
	if (!path || !path[0])
		return NULL;
	int fd = z_openat(AT_FDCWD, path, O_RDONLY);
	if (fd < 0)
		return NULL;
	void *res = load_elf_payload_fd(fd, entry_point_out);
	z_close(fd);
	return res;
}

static int write_all(int fd, const unsigned char *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t n = z_write(fd, buf + off, len - off);
		if (n <= 0)
			return -1;
		off += (size_t)n;
	}
	return 0;
}

static int create_tiny_init_memfd(void)
{
	size_t sz = (size_t)(_binary_tiny_init_tiny_init_end -
			     _binary_tiny_init_tiny_init_start);
	int fd = z_memfd_create("tiny-init", 0);
	if (fd < 0) {
		z_printf("[Loader] tiny-init memfd_create failed errno=%d\n", z_errno);
		return -1;
	}
	if (write_all(fd, _binary_tiny_init_tiny_init_start, sz) < 0)
		goto err;
	if (z_lseek(fd, 0, SEEK_SET) < 0)
		goto err;
	z_printf("[Loader] tiny-init memfd prepared (fd=%d, size=%lu)\n",
		 fd, (unsigned long)sz);
	return fd;
err:
	z_close(fd);
	return -1;
}

static __attribute__((unused)) int create_payload_memfd(void)
{
	size_t sz = (size_t)(_binary_payload_payload_bin_end -
			     _binary_payload_payload_bin_start);
	int fd = z_memfd_create("payload.bin", 0);
	if (fd < 0) {
		z_printf("[Loader] payload memfd_create failed errno=%d\n", z_errno);
		return -1;
	}
	if (write_all(fd, _binary_payload_payload_bin_start, sz) < 0)
		goto err;
	if (z_lseek(fd, 0, SEEK_SET) < 0)
		goto err;
	z_printf("[Loader] Embedded payload prepared (fd=%d, size=%lu)\n",
		 fd, (unsigned long)sz);
	return fd;
err:
	z_close(fd);
	return -1;
}

static int create_shell_memfd(void)
{
	size_t sz = (size_t)(_binary_shell_dash_end -
			     _binary_shell_dash_start);
	int fd = z_memfd_create("compat-shell", 0);
	if (fd < 0) {
		z_printf("[Loader] compat-shell memfd_create failed errno=%d\n", z_errno);
		return -1;
	}
	if (write_all(fd, _binary_shell_dash_start, sz) < 0)
		goto err;
	if (z_lseek(fd, 0, SEEK_SET) < 0)
		goto err;
	z_printf("[Loader] compat-shell memfd prepared (fd=%d, size=%lu)\n",
		 fd, (unsigned long)sz);
	return fd;
err:
	z_close(fd);
	return -1;
}

static __attribute__((unused)) int create_loader_memfd(void)
{
	int src = z_openat(AT_FDCWD, "/proc/self/exe", O_RDONLY);
	if (src < 0) {
		z_printf("[Loader] loader memfd open /proc/self/exe failed errno=%d\n", z_errno);
		return -1;
	}
	int fd = z_memfd_create("elfloader", 0);
	if (fd < 0) {
		z_printf("[Loader] loader memfd_create failed errno=%d\n", z_errno);
		z_close(src);
		return -1;
	}
	unsigned char buf[4096];
	ssize_t n;
	while ((n = z_read(src, buf, sizeof(buf))) > 0) {
		if (write_all(fd, buf, (size_t)n) < 0)
			goto err;
	}
	if (n < 0)
		goto err;
	if (z_lseek(fd, 0, SEEK_SET) < 0)
		goto err;
	z_close(src);
	z_printf("[Loader] loader memfd prepared (fd=%d)\n", fd);
	return fd;
err:
	z_close(src);
	z_close(fd);
	return -1;
}

/* Parse hook range string "A-B" */
static int parse_range_str(const char *s, int *min_out, int *max_out)
{
	if (!s || !min_out || !max_out)
		return 0;
	int a = 0, b = 0x7fffffff;
	const char *dash = z_strchr(s, '-');
	if (dash) {
		a = z_atoi(s);
		b = z_atoi(dash + 1);
	} else {
		a = z_atoi(s);
	}
	if (a < 0)
		a = 0;
	if (b < a)
		b = a;
	*min_out = a;
	*max_out = b;
	return 1;
}

static int clamp_log_level(int level)
{
	if (level < LOG_LEVEL_NONE)
		return LOG_LEVEL_NONE;
	if (level > LOG_LEVEL_DEBUG)
		return LOG_LEVEL_DEBUG;
	return level;
}

static int parse_log_level_value(const char *s)
{
	if (!s)
		return LOG_LEVEL_NONE;
	while (*s == ' ' || *s == '\t')
		s++;
	if (s[0] == '\0')
		return LOG_LEVEL_NONE;
	if (s[0] == 'o' || s[0] == 'O') {
		if (s[1] == 'f' || s[1] == 'F')
			return LOG_LEVEL_NONE;
		return LOG_LEVEL_DEBUG;
	}
	return clamp_log_level(z_atoi(s));
}

typedef struct {
	uint32_t magic;
	uint32_t config_off;
	uint32_t version;
} payload_header_t;

static payload_config_t *locate_payload_config(void *payload_entry)
{
	if (!payload_entry)
		return NULL;

	uint8_t *base = (uint8_t *)payload_entry;
	payload_header_t *hdr = (payload_header_t *)(base + 4); /* skip branch */
	if (hdr->magic != CONFIG_MAGIC || hdr->config_off == 0)
		return NULL;
	if (hdr->version != PAYLOAD_ABI_VERSION)
		z_errx(1, "payload ABI mismatch; rebuild loader and payload together");
	return (payload_config_t *)(base + hdr->config_off);
}

static void copy_substr(char *dst, size_t dst_sz, const char *src, size_t len)
{
	if (!dst || dst_sz == 0)
		return;
	size_t i = 0;
	while (i + 1 < dst_sz && i < len && src[i]) {
		dst[i] = src[i];
		i++;
	}
	dst[i] = '\0';
}

static void copy_cstr(char *dst, size_t dst_sz, const char *src)
{
	if (!src)
		return;
	copy_substr(dst, dst_sz, src, z_strlen(src));
}

static void parse_bind_list(payload_config_t *cfg, const char *val)
{
	if (!cfg || !val)
		return;

	const char *p = val;
	while (*p && cfg->bind_count < CONFIG_MAX_BINDS) {
		const char *comma = z_strchr(p, ',');
		const char *colon = z_strchr(p, ':');
		const char *end = comma ? comma : p + z_strlen(p);

		if (colon && colon < end) {
			if (cfg->bind_count < CONFIG_MAX_BINDS) {
				copy_substr(cfg->binds[cfg->bind_count].src,
					    CONFIG_MAX_PATH, p, (size_t)(colon - p));
				copy_substr(cfg->binds[cfg->bind_count].dst,
					    CONFIG_MAX_PATH, colon + 1, (size_t)(end - colon - 1));
				cfg->bind_count++;
			}
		}

		if (!comma)
			break;
		p = comma + 1;
	}
}

static int parse_mode_value(const char *s)
{
	if (!s)
		return -1;
	if (z_strncmp(s, "container", 10) == 0 && (s[9] == '\0' || s[9] == '\n'))
		return CONFIG_MODE_CONTAINER;
	if (z_strncmp(s, "compat", 7) == 0 && (s[6] == '\0' || s[6] == '\n'))
		return CONFIG_MODE_COMPAT;
	return -1;
}

static void apply_mode(payload_config_t *cfg, int mode, int explicit_flag)
{
	if (!cfg)
		return;
	cfg->mode = mode;
	cfg->hook_mask = HOOK_LAYER_BASE | HOOK_LAYER_COMPAT;
	if (mode == CONFIG_MODE_CONTAINER)
		cfg->hook_mask |= HOOK_LAYER_ISOLATION;
	if (explicit_flag)
		cfg->mode_explicit = 1;
}

static void maybe_set_container_mode(payload_config_t *cfg)
{
	if (!cfg)
		return;
	if (cfg->mode_explicit)
		return;
	if (cfg->mode != CONFIG_MODE_CONTAINER)
		apply_mode(cfg, CONFIG_MODE_CONTAINER, 0);
}

static void init_payload_config(payload_config_t *cfg)
{
	if (cfg)
		z_memset(cfg, 0, sizeof(*cfg));
	if (cfg) {
		cfg->log_level = LOG_LEVEL_NONE;
		cfg->hook_min = 0;
		cfg->hook_max = 0x7fffffff;
		cfg->hook_min_interp = 0;
		cfg->hook_max_interp = 0x7fffffff;
		cfg->loader_norecurse = 1;
		cfg->loader_fd = -1;
#ifdef PROOT_PATH
		cfg->fake_group_count = -1;
#endif
#ifdef FD_EXPERIMENT
		cfg->fd_state = -1;
#endif
		apply_mode(cfg, CONFIG_MODE_COMPAT, 0);
	}
}

static void apply_config_entry(payload_config_t *cfg, const char *entry, char *payload_path_out)
{
	if (!cfg || !entry)
		return;
	if (z_strncmp(entry, "HOOK_LOG=", 9) == 0) {
		cfg->log_level = parse_log_level_value(entry + 9);
	} else if (z_strncmp(entry, "PROOT_ROOT=", 11) == 0) {
		copy_cstr(cfg->root, CONFIG_MAX_PATH, entry + 11);
		maybe_set_container_mode(cfg);
	} else if (z_strncmp(entry, "PROOT_LOWER=", 12) == 0) {
		copy_cstr(cfg->vfs_lower, CONFIG_MAX_PATH, entry + 12);
		maybe_set_container_mode(cfg);
	} else if (z_strncmp(entry, "PROOT_UPPER=", 12) == 0) {
		copy_cstr(cfg->vfs_upper, CONFIG_MAX_PATH, entry + 12);
		maybe_set_container_mode(cfg);
	} else if (z_strncmp(entry, "PROOT_BIND=", 11) == 0) {
		parse_bind_list(cfg, entry + 11);
	} else if (z_strncmp(entry, "PAYLOAD_PATH=", 13) == 0) {
		const char *p = entry + 13;
		if (payload_path_out)
			copy_cstr(payload_path_out, CONFIG_MAX_PATH, p);
		copy_cstr(cfg->payload_path, CONFIG_MAX_PATH, p);
	} else if (z_strncmp(entry, "RUN_MODE=", 9) == 0) {
		int mode = parse_mode_value(entry + 9);
		if (mode >= 0)
			apply_mode(cfg, mode, 1);
	}
}

static void parse_payload_config(payload_config_t *cfg, char **env)
{
	if (!cfg)
		return;

	while (env && *env) {
		apply_config_entry(cfg, *env, NULL);
		env++;
	}
}

/* Host root and bind sources are compared and joined as strings: make them
 * absolute and remove ".", ".." and repeated slashes (PRoot canonicalizes
 * them too). "x/../y" in a bind source otherwise failed every access below
 * it with EINVAL. Symlinks are left to the kernel, as before. */
static void normalize_host_path(char *path, size_t cap)
{
	char joined[CONFIG_MAX_PATH * 2];
	size_t len = 0;
	if (!path[0])
		return;
	if (path[0] != '/') {
		if (!z_getcwd(joined, CONFIG_MAX_PATH))
			return;
		len = z_strlen(joined);
		joined[len++] = '/';
	}
	copy_cstr(joined + len, sizeof(joined) - len, path);
	char out[CONFIG_MAX_PATH];
	size_t o = 0;
	const char *p = joined;
	while (*p) {
		while (*p == '/') p++;
		if (!*p) break;
		const char *q = p;
		while (*q && *q != '/') q++;
		size_t n = (size_t)(q - p);
		if (n == 1 && p[0] == '.') {
		} else if (n == 2 && p[0] == '.' && p[1] == '.') {
			while (o && out[o - 1] != '/') o--;
			if (o) o--;
		} else {
			if (o + n + 2 > sizeof(out))
				return; /* Too long: keep the original spelling. */
			out[o++] = '/';
			z_memcpy(out + o, p, n);
			o += n;
		}
		p = q;
	}
	if (!o)
		out[o++] = '/';
	out[o] = '\0';
	copy_cstr(path, cap, out);
}

static int add_bind_entry(payload_config_t *cfg, const char *guest, const char *host)
{
	if (!cfg || !guest || !host || guest[0] == '\0' || host[0] == '\0')
		return 0;
	if (cfg->bind_count >= CONFIG_MAX_BINDS)
		return 0;
	copy_cstr(cfg->binds[cfg->bind_count].src, CONFIG_MAX_PATH, guest);
	copy_cstr(cfg->binds[cfg->bind_count].dst, CONFIG_MAX_PATH, host);
	cfg->bind_count++;
	return 1;
}

static int add_overlay_entry(payload_config_t *cfg,
			     const char *mount, const char *lower, const char *upper)
{
	if (!cfg || !mount || !lower || !upper ||
	    mount[0] == '\0' || lower[0] == '\0' || upper[0] == '\0')
		return 0;
	if (cfg->overlay_count >= CONFIG_MAX_OVERLAYS)
		return 0;
	copy_cstr(cfg->overlays[cfg->overlay_count].mount, CONFIG_MAX_PATH, mount);
	copy_cstr(cfg->overlays[cfg->overlay_count].lower, CONFIG_MAX_PATH, lower);
	copy_cstr(cfg->overlays[cfg->overlay_count].upper, CONFIG_MAX_PATH, upper);
	cfg->overlay_count++;
	return 1;
}

static int add_env_entry(payload_config_t *cfg, const char *kv)
{
	if (!cfg || !kv || kv[0] == '\0')
		return 0;
	if (cfg->env_count >= CONFIG_MAX_ENVS)
		return 0;
	copy_cstr(cfg->envs[cfg->env_count], CONFIG_MAX_PATH, kv);
	cfg->env_count++;
	return 1;
}

static void load_config_file(payload_config_t *cfg, const char *path, char *payload_path_out)
{
	if (!cfg || !path || !path[0])
		return;
	copy_cstr(cfg->config_path, CONFIG_MAX_PATH, path);
	int fd = z_open(path, O_RDONLY);
	if (fd < 0)
		return;

	char buf[2048];
	ssize_t n = z_read(fd, buf, sizeof(buf));
	z_close(fd);
	if (n <= 0)
		return;

	size_t len = (size_t)n;
	size_t pos = 0;
	while (pos < len) {
		size_t end = pos;
		while (end < len && buf[end] != '\n')
			end++;
		size_t start = pos;
		while (start < end && (buf[start] == ' ' || buf[start] == '\t'))
			start++;
		if (start < end && buf[start] != '#') {
			size_t copy_len = end - start;
			char line[CONFIG_MAX_PATH * 2];
			if (copy_len >= sizeof(line))
				copy_len = sizeof(line) - 1;
			for (size_t i = 0; i < copy_len; i++)
				line[i] = buf[start + i];
			line[copy_len] = '\0';
			while (copy_len > 0 && (line[copy_len - 1] == ' ' ||
						line[copy_len - 1] == '\t' ||
						line[copy_len - 1] == '\r')) {
				line[--copy_len] = '\0';
			}
			if (line[0] != '\0')
				apply_config_entry(cfg, line, payload_path_out);
		}
		pos = end + 1;
	}
}

static int ensure_guest_memfd(int *fd_io)
{
	if (!fd_io)
		return -1;
	if (*fd_io >= 0)
		return *fd_io;
	int fd = z_memfd_create("guest-config", 0);
	if (fd < 0) {
		z_printf("[Loader] guest config memfd_create failed, errno=%d\n", z_errno);
		return -1;
	}
	z_printf("[Loader] guest config memfd created: fd=%d\n", fd);
	*fd_io = fd;
	return fd;
}

static void write_line_memfd(int fd, const char *line)
{
	if (fd < 0 || !line)
		return;
	size_t len = z_strlen(line);
	write_all(fd, (const unsigned char *)line, len);
	write_all(fd, (const unsigned char *)"\n", 1);
	z_printf("[Loader] guest config line: \"%s\"\n", line);
}

static void parse_loader_rc(payload_config_t *cfg, const char *path, char *payload_path_out, int *guest_fd_out)
{
	if (!cfg || !path || !path[0])
		return;

	z_printf("[Loader] parse loader.rc path=\"%s\"\n", path);
	copy_cstr(cfg->config_path, CONFIG_MAX_PATH, path);
	int fd = z_open(path, O_RDONLY);
	if (fd < 0) {
		z_printf("[Loader] failed to open config: %s (errno=%d)\n", path, z_errno);
		return;
	}
	char buf[8192];
	ssize_t n = z_read(fd, buf, sizeof(buf));
	z_close(fd);
	if (n <= 0) {
		z_printf("[Loader] read config failed: rc=%ld errno=%d\n",
			 (long)n, z_errno);
		return;
	}
	size_t len = (size_t)n;
	size_t pos = 0;
	while (pos < len) {
		size_t end = pos;
		while (end < len && buf[end] != '\n')
			end++;
		size_t start = pos;
		while (start < end && (buf[start] == ' ' || buf[start] == '\t'))
			start++;
		size_t line_len = (end > start) ? end - start : 0;
		char line[CONFIG_MAX_PATH * 2];
		if (line_len >= sizeof(line))
			line_len = sizeof(line) - 1;
		for (size_t i = 0; i < line_len; i++)
			line[i] = buf[start + i];
		line[line_len] = '\0';

		if (line_len == 0 || line[0] == '#') {
			pos = end + 1;
			continue;
		}

		if (line[0] == '[') {
			/* 标题注释行，忽略 */
			pos = end + 1;
			continue;
		}

		if (z_strncmp(line, "ROOT ", 5) == 0) {
			copy_cstr(cfg->root, CONFIG_MAX_PATH, line + 5);
			z_printf("[Loader] Host ROOT=\"%s\"\n", cfg->root);
			maybe_set_container_mode(cfg);
		} else if (z_strncmp(line, "LOWER ", 6) == 0) {
			copy_cstr(cfg->vfs_lower, CONFIG_MAX_PATH, line + 6);
			z_printf("[Loader] Host LOWER=\"%s\"\n", cfg->vfs_lower);
			maybe_set_container_mode(cfg);
		} else if (z_strncmp(line, "UPPER ", 6) == 0) {
			copy_cstr(cfg->vfs_upper, CONFIG_MAX_PATH, line + 6);
			z_printf("[Loader] Host UPPER=\"%s\"\n", cfg->vfs_upper);
			maybe_set_container_mode(cfg);
		} else if (z_strncmp(line, "OVERLAY ", 8) == 0) {
			const char *val = line + 8;
			while (*val == ' ' || *val == '\t')
				val++;
			const char *p1 = val;
			while (*val && *val != ' ' && *val != '\t')
				val++;
			const char *p2 = val;
			while (*p2 == ' ' || *p2 == '\t')
				p2++;
			const char *p3 = p2;
			while (*p3 && *p3 != ' ' && *p3 != '\t')
				p3++;
			const char *p4 = p3;
			while (*p4 == ' ' || *p4 == '\t')
				p4++;
			const char *p5 = p4;
			while (*p5 && *p5 != ' ' && *p5 != '\t')
				p5++;

			char mount[CONFIG_MAX_PATH];
			char lower[CONFIG_MAX_PATH];
			char upper[CONFIG_MAX_PATH];
			if (p1 < val && p2 < p3 && p4 < p5) {
				copy_substr(mount, sizeof(mount), p1, (size_t)(val - p1));
				copy_substr(lower, sizeof(lower), p2, (size_t)(p3 - p2));
				copy_substr(upper, sizeof(upper), p4, (size_t)(p5 - p4));
				if (add_overlay_entry(cfg, mount, lower, upper)) {
					z_printf("[Loader] Host OVERLAY %s -> %s (upper=%s)\n",
						 mount, lower, upper);
				}
			}
		} else if (z_strncmp(line, "BIND ", 5) == 0) {
			const char *val = line + 5;
			const char *colon = z_strchr(val, ':');
			if (colon) {
				char left[CONFIG_MAX_PATH];
				char right[CONFIG_MAX_PATH];
				copy_substr(left, sizeof(left), val, (size_t)(colon - val));
				copy_cstr(right, sizeof(right), colon + 1);
				add_bind_entry(cfg, left, right);
				z_printf("[Loader] Host BIND %s -> %s\n", left, right);
			}
		} else if (z_strncmp(line, "DEBUG ", 6) == 0) {
			cfg->log_level = parse_log_level_value(line + 6);
			z_printf("[Loader] Host DEBUG=%d\n", cfg->log_level);
		} else if (z_strncmp(line, "PAYLOAD ", 8) == 0) {
			const char *p = line + 8;
			if (payload_path_out)
				copy_cstr(payload_path_out, CONFIG_MAX_PATH, p);
			copy_cstr(cfg->payload_path, CONFIG_MAX_PATH, p);
			z_printf("[Loader] Host PAYLOAD=\"%s\"\n", cfg->payload_path);
		} else if (z_strncmp(line, "MODE ", 5) == 0) {
			int mode = parse_mode_value(line + 5);
			if (mode >= 0) {
				apply_mode(cfg, mode, 1);
				z_printf("[Loader] Host MODE=%s\n", mode == CONFIG_MODE_CONTAINER ? "container" : "compat");
			}
		} else if (z_strncmp(line, "HOOK_RANGE ", 11) == 0) {
			int a = 0, b = 0x7fffffff;
			if (parse_range_str(line + 11, &a, &b)) {
				cfg->hook_min = a;
				cfg->hook_max = b;
				cfg->hook_range_set = 1;
				z_printf("[Hook] HOOK_RANGE set to [%d - %d]\n", a, b);
			}
		} else if (z_strncmp(line, "HOOK_RANGE_INTERP ", 19) == 0) {
			int a = 0, b = 0x7fffffff;
			if (parse_range_str(line + 19, &a, &b)) {
				cfg->hook_min_interp = a;
				cfg->hook_max_interp = b;
				cfg->hook_range_interp_set = 1;
				z_printf("[Hook] HOOK_RANGE_INTERP set to [%d - %d]\n", a, b);
			}
		} else {
			int gfd = ensure_guest_memfd(guest_fd_out);
			if (gfd >= 0)
				write_line_memfd(gfd, line);
		}

		pos = end + 1;
	}
	if (guest_fd_out && *guest_fd_out >= 0)
		z_lseek(*guest_fd_out, 0, SEEK_SET);
}

static int is_child_loader_arg(const char *arg)
{
	if (!arg)
		return 0;
	size_t key_len = z_strlen(CONFIG_CHILD_LOADER_ARG);
	return z_strncmp(arg, CONFIG_CHILD_LOADER_ARG, key_len) == 0 &&
		arg[key_len] == '\0';
}

typedef struct child_loader_proto {
	const char *exec_target;
	const char *exec_path;
	int exec_dirfd;
	int exec_flags;
	const char *exec_interp;
	const char *exec_exe;
	const char *exec_name;
	int exec_fd;
} child_loader_proto_t;

static const char *find_config_path_arg(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		const char *arg = argv[i];
		if (!arg)
			break;
		if (arg[0] != '-' || arg[1] == '\0')
			break;
		if (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0') {
			i++;
			break;
		}
		if (z_strncmp(arg, "-c", 3) == 0 || z_strncmp(arg, "--config", 9) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			if (argv[i + 1][0] == '-')
				z_errx(1, "invalid config path for %s", arg);
			return argv[i + 1];
		}
		if (z_strncmp(arg, "-v", 3) == 0 || z_strncmp(arg, "--volume", 9) == 0 ||
		    z_strncmp(arg, "-e", 3) == 0 || z_strncmp(arg, "--env", 6) == 0 ||
		    z_strncmp(arg, "-w", 3) == 0 || z_strncmp(arg, "--workdir", 10) == 0 ||
		    z_strncmp(arg, "--root", 7) == 0 || z_strncmp(arg, "--log", 6) == 0 ||
		    z_strncmp(arg, "--hook-range", 13) == 0 ||
		    z_strncmp(arg, "--hook-range-interp", 20) == 0) {
			i++;
			continue;
		}
		if (z_strncmp(arg, CONFIG_CHILD_EXEC_TARGET,
			      z_strlen(CONFIG_CHILD_EXEC_TARGET) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_EXEC_PATH,
			      z_strlen(CONFIG_CHILD_EXEC_PATH) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_EXEC_DIRFD,
			      z_strlen(CONFIG_CHILD_EXEC_DIRFD) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_EXEC_FLAGS,
			      z_strlen(CONFIG_CHILD_EXEC_FLAGS) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_EXEC_INTERP,
			      z_strlen(CONFIG_CHILD_EXEC_INTERP) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_EXEC_EXE,
			      z_strlen(CONFIG_CHILD_EXEC_EXE) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_EXEC_NAME,
			      z_strlen(CONFIG_CHILD_EXEC_NAME) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_GLUE_DIR,
			      z_strlen(CONFIG_CHILD_GLUE_DIR) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_FAKE_IDS,
			      z_strlen(CONFIG_CHILD_FAKE_IDS) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_EXEC_FD,
			      z_strlen(CONFIG_CHILD_EXEC_FD) + 1) == 0 ||
		    z_strncmp(arg, CONFIG_CHILD_FAKE_GROUPS,
			      z_strlen(CONFIG_CHILD_FAKE_GROUPS) + 1) == 0 ||
		    z_strncmp(arg, "--kernel-release", 17) == 0 ||
		    z_strncmp(arg, "--kernel-sysname", 17) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			i++;
			continue;
		}
		if (is_child_loader_arg(arg) || z_strncmp(arg, "--init", 7) == 0 ||
		    z_strncmp(arg, "--link-copy", 12) == 0 ||
		    z_strncmp(arg, "--seccomp-backstop", 19) == 0 ||
		    z_strncmp(arg, "-d", 3) == 0 || z_strncmp(arg, "--detach", 9) == 0) {
			continue;
		}
		break;
	}
	return NULL;
}

static int parse_cli_options(int argc, char **argv, payload_config_t *cfg,
			     int *child_loader_out, int *target_index_out,
			     int *shell_mode_out, child_loader_proto_t *child_proto)
{
	int child_loader = 0;
	int shell_mode = 0;
	int idx = argc;
	if (child_proto) {
		child_proto->exec_target = NULL;
		child_proto->exec_path = NULL;
		child_proto->exec_dirfd = AT_FDCWD;
		child_proto->exec_flags = 0;
		child_proto->exec_interp = NULL;
		child_proto->exec_exe = NULL;
		child_proto->exec_name = NULL;
		child_proto->exec_fd = -1;
	}

	for (int i = 1; i < argc; i++) {
		char *arg = argv[i];
		if (!arg)
			break;
		if (arg[0] != '-' || arg[1] == '\0') {
			idx = i;
			break;
		}
		if (arg[0] == '-' && arg[1] == '-' && arg[2] == '\0') {
			idx = i + 1;
			break;
		}

		if (z_strncmp(arg, "--mode", 7) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			int mode = parse_mode_value(argv[i + 1]);
			if (mode < 0)
				z_errx(1, "invalid mode for %s (expect compat|container)", arg);
			apply_mode(cfg, mode, 1);
			i++;
			continue;
		}

		if (z_strncmp(arg, "-s", 3) == 0 || z_strncmp(arg, "--shell", 8) == 0) {
			shell_mode = 1;
			continue;
		}

#ifdef FD_EXPERIMENT
        if (z_strncmp(arg, "--observe-mount-access", 23) == 0 ||
            z_strncmp(arg, "--guard-path-mutations", 23) == 0 ||
            z_strncmp(arg, "--guard-file-mutations", 23) == 0 ||
            z_strncmp(arg, "--guard-file-access", 20) == 0) {
            if (cfg->mount_access_observe[0]) z_errx(1, "duplicate mount access observation");
            if (i + 1 >= argc) z_errx(1, "missing mount access observation");
            const char *value = argv[++i];
            size_t count = z_strlen(value);
            if (!count || count > CONFIG_MAX_BINDS + 1)
                z_errx(1, "invalid mount access observation length");
            for (size_t j = 0; j < count; j++)
                if (value[j] != 'd' && value[j] != 'r' && value[j] != 'w')
                    z_errx(1, "invalid mount access observation value");
            copy_cstr(cfg->mount_access_observe, sizeof(cfg->mount_access_observe), value);
            cfg->guard_file_reads = z_strncmp(arg, "--guard-file-access", 20) == 0;
            cfg->guard_path_mutations = (cfg->guard_file_reads ||
                z_strncmp(arg, "--guard-file-mutations", 23) == 0) ? 2 :
                z_strncmp(arg, "--guard-path-mutations", 23) == 0;
            continue;
        }
        if (z_strncmp(arg, "--allow-stream-input", 21) == 0) {
            if (cfg->allow_stream_input) z_errx(1, "duplicate stream input option");
            cfg->allow_stream_input = 1;
            continue;
        }
        if (z_strncmp(arg, "--revalidate-file-fds", sizeof("--revalidate-file-fds")) == 0) {
            if (cfg->revalidate_file_fds) z_errx(1, "duplicate file FD revalidation option");
            cfg->revalidate_file_fds = 1;
            continue;
        }
        if (z_strncmp(arg, "--allow-local-output", 21) == 0) {
            if (cfg->allow_local_output) z_errx(1, "duplicate local output option");
            cfg->allow_local_output = 1;
            continue;
        }
        if (z_strncmp(arg, "--allow-pipe-output", 20) == 0) {
            if (cfg->allow_pipe_output) z_errx(1, "duplicate pipe output option");
            cfg->allow_pipe_output = 1;
            continue;
        }
        if (z_strncmp(arg, "--allow-stdio-output", 21) == 0) {
            if (cfg->allow_stdio_output) z_errx(1, "duplicate stdio output option");
            cfg->allow_stdio_output = 1;
            continue;
        }
        if (z_strncmp(arg, "--fd-state", 11) == 0) {
            if (i + 1 >= argc || !argv[i + 1][0]) z_errx(1, "missing fd state");
            unsigned value = 0;
            for (const char *p = argv[++i]; *p; p++) {
                if (*p < '0' || *p > '9' || value > (2147483647u - (*p - '0')) / 10)
                    z_errx(1, "invalid fd state");
                value = value * 10 + (*p - '0');
            }
            cfg->fd_state = (int)value;
            continue;
        }
#endif
		if (is_child_loader_arg(arg)) {
			child_loader = 1;
			continue;
		}

		if (z_strncmp(arg, CONFIG_CHILD_EXEC_TARGET,
			      z_strlen(CONFIG_CHILD_EXEC_TARGET) + 1) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			if (child_proto)
				child_proto->exec_target = argv[i + 1];
			i++;
			continue;
		}

		if (z_strncmp(arg, CONFIG_CHILD_EXEC_PATH,
			      z_strlen(CONFIG_CHILD_EXEC_PATH) + 1) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			if (child_proto)
				child_proto->exec_path = argv[i + 1];
			i++;
			continue;
		}

		if (z_strncmp(arg, CONFIG_CHILD_EXEC_DIRFD,
			      z_strlen(CONFIG_CHILD_EXEC_DIRFD) + 1) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			if (child_proto)
				child_proto->exec_dirfd = z_atoi(argv[i + 1]);
			i++;
			continue;
		}

		if (z_strncmp(arg, CONFIG_CHILD_EXEC_FD,
			      z_strlen(CONFIG_CHILD_EXEC_FD) + 1) == 0) {
			if (i + 1 >= argc || argv[i + 1][0] < '0' || argv[i + 1][0] > '9')
				z_errx(1, "invalid value for %s", arg);
			if (child_proto)
				child_proto->exec_fd = z_atoi(argv[i + 1]);
			i++;
			continue;
		}

		if (z_strncmp(arg, CONFIG_CHILD_EXEC_FLAGS,
			      z_strlen(CONFIG_CHILD_EXEC_FLAGS) + 1) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			if (child_proto)
				child_proto->exec_flags = z_atoi(argv[i + 1]);
			i++;
			continue;
		}

		if (z_strncmp(arg, CONFIG_CHILD_EXEC_NAME,
			      z_strlen(CONFIG_CHILD_EXEC_NAME) + 1) == 0) {
			if (i + 1 >= argc || !argv[i + 1][0])
				z_errx(1, "invalid value for %s", arg);
			if (child_proto)
				child_proto->exec_name = argv[i + 1];
			i++;
			continue;
		}

#ifdef PROOT_PATH
		if (z_strncmp(arg, "--link-copy", 12) == 0) {
			cfg->link_copy = 1;
			continue;
		}
		if (z_strncmp(arg, "--seccomp-backstop", 19) == 0) {
			cfg->seccomp_backstop = 1;
			continue;
		}
		if (z_strncmp(arg, "--kernel-release", 17) == 0 ||
		    z_strncmp(arg, "--kernel-sysname", 17) == 0) {
			char *field = arg[9] == 'r' ? cfg->kernel_release : cfg->kernel_sysname;
			if (i + 1 >= argc || !argv[i + 1][0] || z_strlen(argv[i + 1]) >= 65)
				z_errx(1, "invalid value for %s", arg);
			copy_cstr(field, 65, argv[i + 1]);
			i++;
			continue;
		}
		if (z_strncmp(arg, CONFIG_CHILD_FAKE_GROUPS,
			      z_strlen(CONFIG_CHILD_FAKE_GROUPS) + 1) == 0) {
			const char *p = i + 1 < argc ? argv[i + 1] : NULL;
			int count = 0;
			if (p && !(p[0] == '-' && !p[1])) {
				for (;;) {
					unsigned long long value = 0;
					const char *start = p;
					while (*p >= '0' && *p <= '9' && value <= 0xffffffffULL)
						value = value * 10 + (unsigned)(*p++ - '0');
					if (p == start || value > 0xffffffffULL || count == 32 ||
					    (*p && *p != ',')) {
						p = NULL;
						break;
					}
					cfg->fake_groups[count++] = (uint32_t)value;
					if (!*p) break;
					p++;
				}
			}
			if (!p)
				z_errx(1, "invalid value for %s", arg);
			cfg->fake_group_count = count;
			i++;
			continue;
		}
		if (z_strncmp(arg, CONFIG_CHILD_GLUE_DIR,
			      z_strlen(CONFIG_CHILD_GLUE_DIR) + 1) == 0) {
			if (i + 1 >= argc || argv[i + 1][0] != '/' ||
			    z_strlen(argv[i + 1]) >= CONFIG_MAX_PATH)
				z_errx(1, "invalid value for %s", arg);
			copy_cstr(cfg->glue_dir, CONFIG_MAX_PATH, argv[i + 1]);
			i++;
			continue;
		}
		if (z_strncmp(arg, CONFIG_CHILD_FAKE_IDS,
			      z_strlen(CONFIG_CHILD_FAKE_IDS) + 1) == 0) {
			const char *p = i + 1 < argc ? argv[i + 1] : NULL;
			for (int k = 0; p && k < 8; k++) {
				unsigned long long value = 0;
				const char *start = p;
				while (*p >= '0' && *p <= '9' && value <= 0xffffffffULL)
					value = value * 10 + (unsigned)(*p++ - '0');
				if (p == start || value > 0xffffffffULL ||
				    *p != (k == 7 ? '\0' : ':'))
					p = NULL;
				else {
					cfg->fake_ids[k] = (uint32_t)value;
					p += k < 7;
				}
			}
			if (!p)
				z_errx(1, "invalid value for %s", arg);
			i++;
			continue;
		}
#endif

		if (z_strncmp(arg, CONFIG_CHILD_EXEC_EXE,
			      z_strlen(CONFIG_CHILD_EXEC_EXE) + 1) == 0) {
			if (i + 1 >= argc || argv[i + 1][0] != '/')
				z_errx(1, "invalid value for %s", arg);
			if (child_proto)
				child_proto->exec_exe = argv[i + 1];
			i++;
			continue;
		}

		if (z_strncmp(arg, CONFIG_CHILD_EXEC_INTERP,
			      z_strlen(CONFIG_CHILD_EXEC_INTERP) + 1) == 0) {
			if (i + 1 >= argc || argv[i + 1][0] != '/')
				z_errx(1, "invalid value for %s", arg);
			if (child_proto)
				child_proto->exec_interp = argv[i + 1];
			i++;
			continue;
		}

		if (z_strncmp(arg, "-c", 3) == 0 || z_strncmp(arg, "--config", 9) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			i++;
			continue;
		}

		if (z_strncmp(arg, "--hook-range", 13) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			int a = 0, b = 0x7fffffff;
			if (!parse_range_str(argv[i + 1], &a, &b))
				z_errx(1, "invalid value for %s", arg);
			cfg->hook_min = a;
			cfg->hook_max = b;
			cfg->hook_range_set = 1;
			i++;
			continue;
		}

		if (z_strncmp(arg, "--hook-range-interp", 20) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			int a = 0, b = 0x7fffffff;
			if (!parse_range_str(argv[i + 1], &a, &b))
				z_errx(1, "invalid value for %s", arg);
			cfg->hook_min_interp = a;
			cfg->hook_max_interp = b;
			cfg->hook_range_interp_set = 1;
			i++;
			continue;
		}

		if (z_strncmp(arg, "-v", 3) == 0 || z_strncmp(arg, "--volume", 9) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			const char *val = argv[++i];
			const char *colon = z_strchr(val, ':');
			if (!colon)
				z_errx(1, "volume needs host:container");
			size_t host_len = (size_t)(colon - val);
			char host[CONFIG_MAX_PATH];
			char guest[CONFIG_MAX_PATH];
			copy_substr(host, sizeof(host), val, host_len);
			copy_cstr(guest, sizeof(guest), colon + 1);
			if (!add_bind_entry(cfg, guest, host))
				z_errx(1, "volume exceeds bind limit or invalid");
			continue;
		}

		if (z_strncmp(arg, "-e", 3) == 0 || z_strncmp(arg, "--env", 6) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			const char *kv = argv[++i];
			if (!z_strchr(kv, '='))
				z_errx(1, "env needs KEY=VALUE");
			if (!add_env_entry(cfg, kv))
				z_errx(1, "env exceeds limit or invalid");
			continue;
		}

		if (z_strncmp(arg, "-w", 3) == 0 || z_strncmp(arg, "--workdir", 10) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			copy_cstr(cfg->workdir, CONFIG_MAX_PATH, argv[++i]);
			continue;
		}

		if (z_strncmp(arg, "--root", 7) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			copy_cstr(cfg->root, CONFIG_MAX_PATH, argv[++i]);
			maybe_set_container_mode(cfg);
			continue;
		}

		if (z_strncmp(arg, "--init", 7) == 0) {
			cfg->use_init = 1;
			continue;
		}

		if (z_strncmp(arg, "-d", 3) == 0 || z_strncmp(arg, "--detach", 9) == 0) {
			cfg->detach = 1;
			continue;
		}

		if (z_strncmp(arg, "--log", 6) == 0) {
			if (i + 1 >= argc)
				z_errx(1, "missing value for %s", arg);
			copy_cstr(cfg->log_path, CONFIG_MAX_PATH, argv[++i]);
			continue;
		}

		idx = i;
		break;
	}

	if (child_loader_out)
		*child_loader_out = child_loader;
	if (target_index_out)
		*target_index_out = idx;
	if (shell_mode_out)
		*shell_mode_out = shell_mode;
	return 0;
}
static int has_loader_bind(payload_config_t *cfg)
{
	if (!cfg)
		return 0;
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		if (z_strncmp(cfg->binds[i].src, "/elfloader", CONFIG_MAX_PATH) == 0)
			return 1;
	}
	return 0;
}

static int parse_shebang_at(int dirfd, const char *path, char *interp, size_t interp_sz,
			    char *arg, size_t arg_sz)
{
	if (!path || !interp || interp_sz == 0)
		return 0;
	int fd = z_open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	char buf[256];
	ssize_t n = z_read(fd, buf, sizeof(buf));
	z_close(fd);
	if (n < 2 || buf[0] != '#' || buf[1] != '!')
		return 0;

	size_t pos = 2;
	while (pos < (size_t)n && (buf[pos] == ' ' || buf[pos] == '\t'))
		pos++;

	size_t out = 0;
	while (pos < (size_t)n && buf[pos] != '\n' && buf[pos] != '\r' &&
	       buf[pos] != ' ' && buf[pos] != '\t') {
		if (out + 1 < interp_sz)
			interp[out++] = buf[pos];
		pos++;
	}
	interp[out] = '\0';
	if (out == 0)
		return 0;

	while (pos < (size_t)n && (buf[pos] == ' ' || buf[pos] == '\t'))
		pos++;

	out = 0;
	while (pos < (size_t)n && buf[pos] != '\n' && buf[pos] != '\r') {
		if (out + 1 < arg_sz)
			arg[out++] = buf[pos];
		pos++;
	}
	if (arg && arg_sz)
		arg[out < arg_sz ? out : arg_sz - 1] = '\0';

	return 1;
}

static int is_elf_file_at(int dirfd, const char *path)
{
	if (!path)
		return 0;
	int fd = z_openat(dirfd, path, O_RDONLY);
	if (fd < 0)
		return 0;
	unsigned char ident[4];
	if (z_read(fd, ident, sizeof(ident)) != (ssize_t)sizeof(ident)) {
		z_close(fd);
		return 0;
	}
	z_close(fd);
	return ident[0] == ELFMAG0 && ident[1] == ELFMAG1 &&
	       ident[2] == ELFMAG2 && ident[3] == ELFMAG3;
}

static int is_elf_file(const char *path)
{
	return is_elf_file_at(AT_FDCWD, path);
}

static void log_bind_list(payload_config_t *cfg, const char *tag)
{
	if (!cfg)
		return;
	z_printf("[Loader] %s: root=\"%s\" binds=%d config=\"%s\" payload=\"%s\"\n",
		 tag ? tag : "config", cfg->root, cfg->bind_count,
		 cfg->config_path, cfg->payload_path);
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		z_printf("[Loader]   bind[%d]: %s -> %s\n", i,
			 cfg->binds[i].src, cfg->binds[i].dst);
	}
}

static int resolve_self_path(char *out, size_t out_sz, const char *argv0)
{
	if (!out || out_sz == 0)
		return 0;
	out[0] = '\0';

	const char *candidates[] = {
		"/proc/self/exe",
		"/proc/curproc/file",
		"/proc/self/path/a.out",
		NULL
	};
	for (int i = 0; candidates[i]; i++) {
		ssize_t n = z_readlink(candidates[i], out, out_sz - 1);
		if (n > 0) {
			if ((size_t)n >= out_sz)
				n = out_sz - 1;
			out[n] = '\0';
			return 1;
		}
	}

	if (!argv0 || !argv0[0])
		return 0;

	if (argv0[0] == '/') {
		copy_cstr(out, out_sz, argv0);
		return 1;
	}

	char cwd[CONFIG_MAX_PATH];
	if (z_getcwd(cwd, sizeof(cwd))) {
		size_t pos = 0;
		for (; cwd[pos] && pos + 1 < out_sz; pos++)
			out[pos] = cwd[pos];
		if (pos > 0 && out[pos - 1] != '/' && pos + 1 < out_sz)
			out[pos++] = '/';
		for (size_t i = 0; argv0[i] && pos + 1 < out_sz; i++)
			out[pos++] = argv0[i];
		out[pos] = '\0';
		return 1;
	}

	copy_cstr(out, out_sz, argv0);
	return 1;
}

static int get_path_stat(const char *path, unsigned long long *dev_out,
			 unsigned long long *ino_out)
{
	if (!path || !dev_out || !ino_out)
		return 0;
	struct stat st;
	if (z_newfstatat(AT_FDCWD, path, &st, 0) < 0)
		return 0;
	*dev_out = (unsigned long long)st.st_dev;
	*ino_out = (unsigned long long)st.st_ino;
	return 1;
}

static int has_prefix(const char *path, const char *prefix)
{
	size_t plen = z_strlen(prefix);
	if (plen == 0)
		return 0;
	if (z_strncmp(path, prefix, plen) != 0)
		return 0;
	char tail = path[plen];
	return tail == '\0' || tail == '/' ? 1 : 0;
}

static size_t join_paths(char *out, size_t out_sz,
			 const char *left, size_t left_len,
			 const char *right)
{
	size_t pos = 0;

	if (!out || out_sz == 0)
		return 0;

	while (pos + 1 < out_sz && left && pos < left_len) {
		out[pos] = left[pos];
		pos++;
	}

	if (!right || right[0] == '\0') {
		out[pos] = '\0';
		return pos;
	}

	int left_slash = (pos > 0 && out[pos - 1] == '/');
	int right_slash = (right && right[0] == '/');

	if (!left_slash && !right_slash) {
		if (pos + 1 < out_sz)
			out[pos++] = '/';
	} else if (left_slash && right_slash) {
		right++;
	}

	size_t i = 0;
	while (pos + 1 < out_sz && right && right[i]) {
		out[pos++] = right[i++];
	}
	out[pos] = '\0';
	return pos;
}

static size_t dirname_len(const char *path)
{
	size_t len = z_strlen(path);
	for (size_t i = len; i > 0; i--) {
		if (path[i - 1] == '/') {
			return (i == 1) ? 1 : i - 1;
		}
	}
	return 0;
}

static void build_rooted_path(payload_config_t *cfg, const char *path,
			      char *out, size_t out_sz)
{
	if (!out || out_sz == 0)
		return;
	if (!path) {
		out[0] = '\0';
		return;
	}
	if (!cfg || cfg->root[0] == '\0') {
		copy_cstr(out, out_sz, path);
		return;
	}
	if (has_prefix(path, cfg->root)) {
		copy_cstr(out, out_sz, path);
		return;
	}
	join_paths(out, out_sz, cfg->root, z_strlen(cfg->root), path);
}

static const char *resolve_child_loader_path(payload_config_t *cfg,
					     const char *path,
					     int is_child_loader,
					     char *out, size_t out_sz)
{
	if (!is_child_loader || !cfg || cfg->root[0] == '\0' ||
	    !path || !out || out_sz == 0)
		return path;

	char current[CONFIG_MAX_PATH];
	char target[CONFIG_MAX_PATH];
	char cwd_buf[CONFIG_MAX_PATH];
	const char *base = NULL;

	if (path[0] == '/') {
		build_rooted_path(cfg, path, current, sizeof(current));
	} else {
		if (z_getcwd(cwd_buf, sizeof(cwd_buf))) {
			base = cwd_buf;
			z_printf("[Loader]   cwd for resolve: \"%s\"\n", base);
		}
		if (base && has_prefix(base, cfg->root)) {
			join_paths(current, sizeof(current), base, z_strlen(base), path);
		} else if (cfg->root[0]) {
			join_paths(current, sizeof(current), cfg->root, z_strlen(cfg->root), path);
		} else if (base) {
			join_paths(current, sizeof(current), base, z_strlen(base), path);
		} else {
			copy_cstr(current, sizeof(current), path);
		}
	}

	z_printf("[Loader] child=%d resolve path \"%s\" -> start \"%s\"\n",
		 is_child_loader, path ? path : "(null)", current);

	for (int depth = 0; depth < SYMLINK_MAX_DEPTH; depth++) {
		ssize_t n = z_readlink(current, target, sizeof(target) - 1);
		if (n < 0) {
			z_printf("[Loader]   readlink failed on \"%s\": rc=%ld errno=%d\n",
				 current, (long)n, z_errno);
			if (z_errno == EINVAL)
				break; /* not a symlink */
			break;
		}
		if ((size_t)n >= sizeof(target))
			n = sizeof(target) - 1;
		target[n] = '\0';
		if (target[0] == '\0')
			break;

		z_printf("[Loader]   link hop %d: \"%s\" -> \"%s\"%s\n",
			 depth, current, target, target[0] == '/' ? " (abs)" : " (rel)");

		if (target[0] == '/') {
			join_paths(current, sizeof(current), cfg->root,
				   z_strlen(cfg->root), target);
		} else {
			size_t dir_len = dirname_len(current);
			join_paths(current, sizeof(current), current, dir_len, target);
		}
	}

	z_printf("[Loader] child=%d final resolved \"%s\"\n",
		 is_child_loader, current);

	copy_cstr(out, out_sz, current);
	return out;
}

static int apply_bind_overlay(payload_config_t *cfg, char *out, size_t out_sz, const char *in_path)
{
	if (!cfg)
		return 0;
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		const char *src = cfg->binds[i].src;
		const char *dst = cfg->binds[i].dst;
		size_t src_len = z_strlen(src);
		if (src_len == 0 || !has_prefix(in_path, src))
			continue;
		const char *suffix = in_path + src_len;
		join_paths(out, out_sz, dst, z_strlen(dst), suffix);
		return 1;
	}
	return 0;
}

static void apply_root_overlay(payload_config_t *cfg, char *out, size_t out_sz)
{
	if (!cfg || !out || out_sz == 0)
		return;
	if (cfg->root[0] == '\0' || out[0] != '/')
		return;
	if (has_prefix(out, cfg->root))
		return;
	char original[CONFIG_MAX_PATH];
	copy_cstr(original, sizeof(original), out);
	join_paths(out, out_sz, cfg->root, z_strlen(cfg->root), original);
}

/* Host path of a canonical guest path: the longest bind, else the root. */
static int map_guest_path(payload_config_t *cfg, const char *guest, char *out, size_t out_sz)
{
	size_t best = 0;
	int found = -1;
	for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
		size_t len = z_strlen(cfg->binds[i].src);
		if (len > best && has_prefix(guest, cfg->binds[i].src)) {
			best = len;
			found = i;
		}
	}
	const char *host = found >= 0 ? cfg->binds[found].dst : cfg->root;
	const char *rest = guest + best;
	size_t host_len = z_strlen(host), rest_len = z_strlen(rest);
	if (host_len + rest_len + 2 > out_sz)
		return -1;
	z_memcpy(out, host, host_len);
	if (host_len && rest[0] == '/' && host[host_len - 1] == '/')
		rest++, rest_len--;
	z_memcpy(out + host_len, rest, rest_len + 1);
	if (!out[0])
		copy_cstr(out, out_sz, "/");
	return 0;
}

/* PRoot semantics for a guest path the loader opens itself (PT_INTERP):
 * resolve component by component through binds and root, following every
 * symlink in guest terms, so an absolute link inside the rootfs cannot
 * escape to the host. Lexical mapping is the fallback on failure. */
static int resolve_guest_path(payload_config_t *cfg, const char *guest, char *out, size_t out_sz)
{
	char done[CONFIG_MAX_PATH], pending[CONFIG_MAX_PATH * 2];
	char link[CONFIG_MAX_PATH], host[CONFIG_MAX_PATH];
	size_t done_len = 0;
	int links = 0;
	if (guest[0] != '/' || z_strlen(guest) >= sizeof(pending))
		return -1;
	copy_cstr(pending, sizeof(pending), guest);
	done[0] = '\0';
	char *cursor = pending;
	while (*cursor) {
		while (*cursor == '/')
			cursor++;
		if (!*cursor)
			break;
		char *next = cursor;
		while (*next && *next != '/')
			next++;
		size_t len = (size_t)(next - cursor);
		if (len == 1 && cursor[0] == '.') {
			cursor = next;
			continue;
		}
		if (len == 2 && cursor[0] == '.' && cursor[1] == '.') {
			while (done_len && done[done_len - 1] != '/')
				done_len--;
			if (done_len)
				done_len--;
			done[done_len] = '\0';
			cursor = next;
			continue;
		}
		size_t start = done_len;
		if (done_len + len + 2 > sizeof(done))
			return -1;
		done[done_len++] = '/';
		z_memcpy(done + done_len, cursor, len);
		done_len += len;
		done[done_len] = '\0';
		cursor = next;
		if (map_guest_path(cfg, done, host, sizeof(host)) < 0)
			return -1;
		ssize_t n = z_readlink(host, link, sizeof(link) - 1);
		if (n < 0)
			continue; /* Not a link (or missing: the open reports it). */
		if (n == 0 || ++links > 40)
			return -1;
		link[n] = '\0';
		/* Splice the link body in front of the unresolved remainder. */
		size_t rest = z_strlen(cursor);
		if ((size_t)n + rest + 2 > sizeof(pending))
			return -1;
		char remainder[CONFIG_MAX_PATH * 2];
		copy_cstr(remainder, sizeof(remainder), cursor);
		z_memcpy(pending, link, (size_t)n);
		pending[n] = '/';
		z_memcpy(pending + n + 1, remainder, rest + 1);
		cursor = pending;
		done_len = link[0] == '/' ? 0 : start;
		done[done_len] = '\0';
	}
	if (!done_len)
		copy_cstr(done, sizeof(done), "/");
	return map_guest_path(cfg, done, out, out_sz);
}

static const char *rewrite_interp_path(payload_config_t *cfg, const char *in, char *out, size_t out_sz)
{
	if (!cfg || !in || !out || out_sz == 0)
		return in;
#ifdef PROOT_PATH
	if ((cfg->root[0] || cfg->bind_count) && !resolve_guest_path(cfg, in, out, out_sz))
		return out;
#endif
	copy_substr(out, out_sz, in, z_strlen(in));
	if (!apply_bind_overlay(cfg, out, out_sz, in))
		apply_root_overlay(cfg, out, out_sz);
	return out;
}

void z_entry(unsigned long *sp, void (*fini)(void))
{
	Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
	Elf_Phdr *phdr, *iter;
	Elf_auxv_t *av;
	char **argv, **env, **p, *elf_interp = NULL;
	char interp_path[CONFIG_MAX_PATH];
	char open_path[CONFIG_MAX_PATH];
	char shebang_interp[CONFIG_MAX_PATH];
	char shebang_interp_arg[CONFIG_MAX_PATH];
	char shebang_script[CONFIG_MAX_PATH];
	unsigned long base[2], entry[2];
	const char *file;
	ssize_t sz;
	int argc, fd, i;
	int load_interp_next = 0;
	int child_loader = 0;
	child_loader_proto_t child_proto;
	int shebang_mode = 0;
	int shell_mode = 0;
	int init_memfd = -1;
	int shell_memfd = -1;
	int loader_memfd = -1;

	void *payload_base = NULL;
	size_t payload_entry_addr = 0;
	payload_config_t *payload_cfg = NULL;

	(void)fini;

	/* Quiet until the configuration says otherwise. */
	z_printf_enabled = 0;
	argc = (int)*(sp);
	argv = (char **)(sp + 1);
	env = p = (char **)&argv[argc + 1];

	while (*p++ != NULL)
		;
	av = (void *)p;
	Elf_auxv_t *av_start = av;

	(void)env;
	const char *config_path = CONFIG_DEFAULT_CONFIG_PATH;
	char loader_path_buf[CONFIG_MAX_PATH];
	const char *loader_path = NULL;
	if (resolve_self_path(loader_path_buf, sizeof(loader_path_buf),
			      (argc > 0) ? argv[0] : NULL)) {
		loader_path = loader_path_buf;
	}
	char payload_path_override[CONFIG_MAX_PATH];
	z_memset(payload_path_override, 0, sizeof(payload_path_override));
	payload_config_t bootstrap_cfg;
	init_payload_config(&bootstrap_cfg);
	static char clean_env_store[CONFIG_MAX_ENVS][CONFIG_MAX_PATH];
	static char *clean_env_ptrs[CONFIG_MAX_ENVS + 1];
	char **compat_env_ptrs = NULL;
	int compat_envc = 0;
	int guest_cfg_fd = -1;
	const char *cli_cfg = find_config_path_arg(argc, argv);
	if (cli_cfg)
		config_path = cli_cfg;
	parse_loader_rc(&bootstrap_cfg, config_path, payload_path_override, &guest_cfg_fd);
	int target_index = 0;
	parse_cli_options(argc, argv, &bootstrap_cfg, &child_loader, &target_index,
			  &shell_mode, &child_proto);
	z_printf_enabled = bootstrap_cfg.log_level != LOG_LEVEL_NONE;
#ifdef PROOT_PATH
	hook_set_section_scan(bootstrap_cfg.seccomp_backstop);
#endif
	if (bootstrap_cfg.root[0])
		normalize_host_path(bootstrap_cfg.root, CONFIG_MAX_PATH);
	for (int i = 0; i < bootstrap_cfg.bind_count && i < CONFIG_MAX_BINDS; i++)
		normalize_host_path(bootstrap_cfg.binds[i].dst, CONFIG_MAX_PATH);
#ifdef FD_EXPERIMENT
    if (bootstrap_cfg.mount_access_observe[0] &&
        z_strlen(bootstrap_cfg.mount_access_observe) != (size_t)bootstrap_cfg.bind_count + 1)
        z_errx(1, "mount access observation requires root plus every bind");
    if (bootstrap_cfg.revalidate_file_fds && bootstrap_cfg.guard_path_mutations != 2)
        z_errx(1, "file FD revalidation requires file mutation guard");
    if (bootstrap_cfg.allow_local_output && bootstrap_cfg.guard_path_mutations != 2)
        z_errx(1, "local output requires file mutation guard");
    if (bootstrap_cfg.allow_pipe_output && bootstrap_cfg.guard_path_mutations != 2)
        z_errx(1, "pipe output requires file mutation guard");
    if (bootstrap_cfg.allow_stdio_output && bootstrap_cfg.guard_path_mutations != 2)
        z_errx(1, "stdio output requires file mutation guard");
    if (bootstrap_cfg.allow_stream_input && !bootstrap_cfg.guard_file_reads)
        z_errx(1, "stream input requires file access guard");
    if (bootstrap_cfg.fd_state >= 0 && !child_loader)
        z_errx(1, "fd state requires child loader");
    if (child_proto.exec_interp && (!child_loader || !bootstrap_cfg.guard_file_reads))
        z_errx(1, "exec interpreter requires file access child loader");
#else
    if (child_proto.exec_interp)
        z_errx(1, "exec interpreter requires file access child loader");
#endif
	int argi = target_index;
	int has_config = (config_path && config_path[0]) ? 1 : 0;
	const char *child_exec_target = child_proto.exec_target;
	const char *child_exec_path = child_proto.exec_path;
	int child_exec_dirfd = child_proto.exec_dirfd;
	int child_exec_flags = child_proto.exec_flags;

	if (shell_mode) {
		apply_mode(&bootstrap_cfg, CONFIG_MODE_COMPAT, 1);
		if (bootstrap_cfg.use_init) {
			z_printf("[Loader] --shell disables --init\n");
			bootstrap_cfg.use_init = 0;
		}
	}

#ifdef PROOT_PATH
	/* The PRoot backends re-exec loader_path; only the legacy exec handler
	 * uses this copy, which would also stay open in every guest. */
	loader_memfd = -1;
#else
	loader_memfd = create_loader_memfd();
#endif
	bootstrap_cfg.loader_fd = loader_memfd;
	bootstrap_cfg.loader_norecurse = 1;
	if (loader_path) {
		copy_cstr(bootstrap_cfg.loader_path, CONFIG_MAX_PATH, loader_path);
		unsigned long long dev = 0, ino = 0;
		if (get_path_stat(loader_path, &dev, &ino)) {
			bootstrap_cfg.loader_dev = dev;
			bootstrap_cfg.loader_ino = ino;
		}
	}
	/* Apply hook ranges from config/CLI */
	g_hook_min_default = bootstrap_cfg.hook_min;
	g_hook_max_default = bootstrap_cfg.hook_max;
	g_hook_min_interp = bootstrap_cfg.hook_min_interp;
	g_hook_max_interp = bootstrap_cfg.hook_max_interp;
	set_hook_log_level(bootstrap_cfg.log_level);
	if (bootstrap_cfg.log_level != LOG_LEVEL_NONE) {
		g_loader_version = generate_loader_version();
		z_printf("[Loader] build version %lx\n", g_loader_version);
	}
	int compat_mode = (bootstrap_cfg.mode == CONFIG_MODE_COMPAT);
	int clean_envc = 0;
	for (int i = 0; i < bootstrap_cfg.env_count && i < CONFIG_MAX_ENVS; i++) {
		copy_cstr(clean_env_store[clean_envc], CONFIG_MAX_PATH, bootstrap_cfg.envs[i]);
		clean_env_ptrs[clean_envc] = clean_env_store[clean_envc];
		clean_envc++;
	}
	clean_env_ptrs[clean_envc] = NULL;
	if (bootstrap_cfg.use_init && guest_cfg_fd >= 0 && clean_envc + 1 < CONFIG_MAX_ENVS) {
		static char fd_env[32];
		int v = guest_cfg_fd;
		int pos = 0;
		const char *prefix = "INIT_CONFIG_FD=";
		while (prefix[pos]) {
			fd_env[pos] = prefix[pos];
			pos++;
		}
		char numbuf[16];
		int npos = 0;
		if (v == 0) {
			numbuf[npos++] = '0';
		} else {
			int tmp = v;
			char rev[16];
			int rpos = 0;
			while (tmp > 0 && rpos < (int)sizeof(rev)) {
				rev[rpos++] = '0' + (tmp % 10);
				tmp /= 10;
			}
			while (rpos > 0)
				numbuf[npos++] = rev[--rpos];
		}
		for (int i = 0; i < npos && pos + 1 < (int)sizeof(fd_env); i++)
			fd_env[pos++] = numbuf[i];
		fd_env[pos] = '\0';
		copy_cstr(clean_env_store[clean_envc], CONFIG_MAX_PATH, fd_env);
		clean_env_ptrs[clean_envc] = clean_env_store[clean_envc];
		clean_envc++;
		clean_env_ptrs[clean_envc] = NULL;
	}
	char **final_env_ptrs = clean_env_ptrs;
	int final_envc = clean_envc;
	int preserve_exec_env = compat_mode;
#ifdef PROOT_PATH
	/* A guest exec supplies its environment explicitly, including empty env. */
	preserve_exec_env = preserve_exec_env || child_loader;
#endif
	if (preserve_exec_env) {
		/* 兼容模式：保留宿主环境，再追加/覆盖 CLI 或配置注入的环境变量 */
		int parent_envc = 0;
		while (env && env[parent_envc])
			parent_envc++;
		int max_envc = parent_envc + clean_envc;
		compat_env_ptrs = z_alloca(sizeof(char *) * (max_envc + 1));
		for (int i = 0; i < parent_envc; i++)
			compat_env_ptrs[compat_envc++] = env[i];
		for (int i = 0; i < clean_envc; i++) {
			const char *kv = clean_env_store[i];
			size_t key_len = 0;
			while (kv[key_len] && kv[key_len] != '=')
				key_len++;
			int replaced = 0;
			for (int j = 0; j < compat_envc; j++) {
				size_t exist_len = 0;
				while (compat_env_ptrs[j][exist_len] && compat_env_ptrs[j][exist_len] != '=')
					exist_len++;
				if (exist_len == key_len &&
				    z_strncmp(compat_env_ptrs[j], kv, key_len) == 0) {
					compat_env_ptrs[j] = (char *)kv;
					replaced = 1;
					break;
				}
			}
			if (!replaced)
				compat_env_ptrs[compat_envc++] = clean_env_store[i];
		}
		compat_env_ptrs[compat_envc] = NULL;
		final_env_ptrs = compat_env_ptrs;
		final_envc = compat_envc;
	}
	log_bind_list(&bootstrap_cfg, "config loaded");
	const char *argv_target = (shell_mode || argi >= argc || !argv[argi]) ?
		"(none)" : argv[argi];
	const char *exec_target_log = child_exec_target ?
		child_exec_target : argv_target;
	z_printf("[Loader] child_loader=%d argv_target=\"%s\" exec_target=\"%s\" payload_path_override=\"%s\" shell=%d\n",
		 child_loader,
		 argv_target,
		 exec_target_log,
		 payload_path_override[0] ? payload_path_override : "(none)",
		 shell_mode);
	/* 主 loader 才主动 chdir 到 root；子 loader 保留调用方 cwd 以正确解析相对路径 */
	if (bootstrap_cfg.root[0] && !child_loader) {
		if (z_chdir(bootstrap_cfg.root) < 0)
			z_errx(1, "chdir to root %s failed", bootstrap_cfg.root);
	}
	if (!has_config && bootstrap_cfg.use_init)
		z_errx(1, "--init requires a config (-c)");
	if (!shell_mode && !has_config && argi >= argc)
		z_errx(1, "no input file");
	if (!shell_mode && has_config && !bootstrap_cfg.use_init && argi >= argc)
		z_errx(1, "no input file");
	if (bootstrap_cfg.use_init) {
		file = CONFIG_DEFAULT_INIT_PATH;
	} else if (shell_mode) {
		file = "(embedded shell)";
	} else {
		const char *default_target = (argi < argc) ? argv[argi] : NULL;
		file = child_exec_target ? child_exec_target : default_target;
	}
#ifdef PROOT_PATH
	/* /proc/<pid>/exe in guest terms. The exec chain names it; an initial
	 * target is a host path relative to the root (or the guest path itself
	 * without one). Loader-side shebang targets keep their interpreter name. */
	/* PRoot's glue lives in PROOT_TMP_DIR, else TMPDIR, else /tmp. The
	 * exec chain keeps the initial choice whatever the guest environment. */
	if (!child_loader && !bootstrap_cfg.glue_dir[0]) {
		const char *base = NULL;
		for (int pass = 0; pass < 2 && !base; pass++) {
			const char *key = pass ? "TMPDIR=" : "PROOT_TMP_DIR=";
			size_t key_length = z_strlen(key);
			for (char **e = env; e && *e; e++)
				if (z_strncmp(*e, key, key_length) == 0 && (*e)[key_length] == '/' &&
				    z_strlen(*e + key_length) < CONFIG_MAX_PATH) {
					base = *e + key_length;
					break;
				}
		}
		copy_cstr(bootstrap_cfg.glue_dir, CONFIG_MAX_PATH, base ? base : "/tmp");
	}
	if (child_proto.exec_exe) {
		copy_cstr(bootstrap_cfg.exec_exe, CONFIG_MAX_PATH, child_proto.exec_exe);
	} else if (child_exec_path) {
		copy_cstr(bootstrap_cfg.exec_exe, CONFIG_MAX_PATH, child_exec_path);
	} else if (file && !shell_mode && !bootstrap_cfg.use_init) {
		const char *name = file;
		while (name[0] == '.' && name[1] == '/') {
			name += 2;
			while (*name == '/') name++;
		}
		if (name[0] == '/') {
			copy_cstr(bootstrap_cfg.exec_exe, CONFIG_MAX_PATH, name);
		} else if (bootstrap_cfg.root[0]) {
			bootstrap_cfg.exec_exe[0] = '/';
			copy_cstr(bootstrap_cfg.exec_exe + 1, CONFIG_MAX_PATH - 1, name);
		} else if (z_getcwd(bootstrap_cfg.exec_exe, CONFIG_MAX_PATH)) {
			join_paths(bootstrap_cfg.exec_exe, CONFIG_MAX_PATH, bootstrap_cfg.exec_exe,
				   z_strlen(bootstrap_cfg.exec_exe), name);
		}
	}
#endif
	if (bootstrap_cfg.root[0] && file && file[0] == '/' && !child_loader && !shell_mode)
		z_errx(1, "absolute path not allowed when PROOT_ROOT is set; use path relative to root");
	char **target_argv = NULL;
	if (shell_mode) {
		int shell_argc = argc - argi;
		if (shell_argc < 0)
			shell_argc = 0;
		target_argv = z_alloca(sizeof(char *) * (shell_argc + 2));
		int pos = 0;
		target_argv[pos++] = (char *)"dash";
		for (int k = 0; k < shell_argc; k++)
			target_argv[pos++] = argv[argi + k];
		target_argv[pos] = NULL;
	} else {
		static char *empty_argv[] = { NULL };
		target_argv = (argi < argc) ? &argv[argi] : empty_argv;
	}

	if (bootstrap_cfg.use_init) {
		init_memfd = create_tiny_init_memfd();
		if (init_memfd < 0)
			z_errx(1, "failed to prepare embedded tiny-init");
		if (guest_cfg_fd < 0 && argi >= argc)
			z_errx(1, "guest config not available (memfd_create missing?) and no target provided");
	}
	if (shell_mode) {
		shell_memfd = create_shell_memfd();
		if (shell_memfd < 0)
			z_errx(1, "failed to prepare embedded compat shell");
	}

	const char *payload_path = payload_path_override[0] ? payload_path_override : CONFIG_DEFAULT_PAYLOAD_PATH;
	const char *payload_source = payload_path_override[0] ? payload_path_override : "(embedded)";
	int used_embedded = 0;

	if (payload_path_override[0]) {
		z_printf("[Loader] Loading payload.bin from custom path \"%s\"...\n", payload_path);
		payload_base = load_elf_payload_path(payload_path, &payload_entry_addr);
	} else {
		z_printf("[Loader] Loading embedded payload...\n");
		/* Straight from the embedded image: no memfd copy per exec. */
		payload_base = load_elf_payload_src(-1, _binary_payload_payload_bin_start,
						    (size_t)(_binary_payload_payload_bin_end -
							     _binary_payload_payload_bin_start),
						    &payload_entry_addr);
		if (payload_base) {
			used_embedded = 1;
		} else {
			z_printf("[Loader] Embedded payload load failed, trying fallback path \"%s\"...\n",
				 payload_path);
			payload_base = load_elf_payload_path(payload_path, &payload_entry_addr);
			payload_source = payload_path;
		}
	}

	if (!payload_base) {
		z_printf("[Loader] Warning: payload.bin not found or invalid.\n");
	} else {
		z_printf("[Loader] Payload loaded from %s. Base: %p, Entry: %p\n",
			 payload_source, payload_base, (void *)payload_entry_addr);
		payload_cfg = locate_payload_config((void *)payload_entry_addr);
		if (payload_cfg) {
			init_payload_config(payload_cfg);
			z_memcpy(payload_cfg, &bootstrap_cfg, sizeof(*payload_cfg));
			if (!payload_path_override[0] && used_embedded)
				copy_cstr(payload_cfg->payload_path, CONFIG_MAX_PATH, "(embedded)");
			log_bind_list(payload_cfg, "payload config");
		} else {
			z_printf("[Loader] Warning: payload config block not found.\n");
		}
	}

	for (i = 0;; i++, ehdr++) {
		int loading_interp = load_interp_next;
		fd = -1;
		const char *path_for_open = NULL;
		const char *base_path = file;
		if (loading_interp)
			set_hook_range(g_hook_min_interp, g_hook_max_interp);
		else
			set_hook_range(g_hook_min_default, g_hook_max_default);
		if (shell_mode && !loading_interp) {
			path_for_open = "(embedded shell)";
			fd = shell_memfd;
		} else if (bootstrap_cfg.use_init && !loading_interp) {
			path_for_open = "(embedded tiny-init)";
			fd = init_memfd;
		} else if (child_loader && child_exec_target) {
			/* 已由 payload 重写/定位的路径，避免重复套 ROOT/BIND */
			copy_cstr(open_path, sizeof(open_path), base_path ? base_path : "");
			path_for_open = open_path;
		} else {
			if (child_exec_dirfd == AT_FDCWD || (base_path && base_path[0] == '/')) {
				path_for_open = resolve_child_loader_path(&bootstrap_cfg,
						base_path, child_loader, open_path, sizeof(open_path));
			} else {
				copy_cstr(open_path, sizeof(open_path), base_path ? base_path : "");
				path_for_open = open_path;
			}
		}
		z_printf("[Loader] child=%d open target \"%s\" (arg=\"%s\" dirfd=%d flags=0x%x)\n",
			 child_loader, path_for_open, file, child_exec_dirfd, child_exec_flags);
		if (!bootstrap_cfg.use_init && !shell_mode && child_loader && !loading_interp && !shebang_mode) {
			z_memset(shebang_interp, 0, sizeof(shebang_interp));
			z_memset(shebang_interp_arg, 0, sizeof(shebang_interp_arg));
			if (parse_shebang_at(child_exec_dirfd, path_for_open,
					     shebang_interp, sizeof(shebang_interp),
					     shebang_interp_arg, sizeof(shebang_interp_arg))) {
				copy_cstr(shebang_script, sizeof(shebang_script), path_for_open);
				char resolved_interp[CONFIG_MAX_PATH];
				if (shebang_interp[0] == '/') {
					resolve_child_loader_path(&bootstrap_cfg, shebang_interp,
								  child_loader, resolved_interp, sizeof(resolved_interp));
				} else {
					size_t dir_len = dirname_len(path_for_open);
					join_paths(resolved_interp, sizeof(resolved_interp),
						   path_for_open, dir_len, shebang_interp);
				}
				copy_cstr(shebang_interp, sizeof(shebang_interp), resolved_interp);
				z_printf("[Loader] shebang: script=\"%s\" interp=\"%s\" arg=\"%s\"\n",
					 shebang_script, shebang_interp, shebang_interp_arg);
				file = shebang_interp;
				shebang_mode = 1;
				/* Restart loop with interpreter path */
				i--;
				continue;
			}
		}
		if (child_loader && !bootstrap_cfg.use_init && !shell_mode) {
			int elf = is_elf_file_at(child_exec_dirfd, path_for_open);
			z_printf("[Loader] child=%d ELF check \"%s\": %s\n",
				 child_loader, path_for_open, elf ? "yes" : "no");
			if (!elf) {
				z_errx(1, "target is not ELF: %s", path_for_open);
			}
		}
		if (fd < 0) {
			int open_flags = O_RDONLY;
			if (child_exec_flags & AT_SYMLINK_NOFOLLOW)
				open_flags |= O_NOFOLLOW;
			if ((fd = z_openat(child_exec_dirfd, path_for_open, open_flags)) < 0)
				z_errx(1, "can't open %s", path_for_open);
		}
		if (z_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
			z_errx(1, "can't read ELF header %s", file);
		if (!check_ehdr(ehdr))
			z_errx(1, "bogus ELF header %s", file);

		sz = ehdr->e_phnum * sizeof(Elf_Phdr);
		phdr = z_alloca(sz);
		if (z_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0)
			z_errx(1, "can't lseek to program header %s", file);
		if (z_read(fd, phdr, sz) != sz)
			z_errx(1, "can't read program header %s", file);

		if ((base[i] = loadelf_anon(fd, ehdr, phdr, (void *)payload_entry_addr, 0)) == LOAD_ERR)
			z_errx(1, "can't load ELF %s", file);

		entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
		if (loading_interp) {
			z_close(fd);
			break;
		}

		for (iter = phdr; !loading_interp && iter < &phdr[ehdr->e_phnum]; iter++) {
			if (iter->p_type != PT_INTERP)
				continue;
			elf_interp = z_alloca(iter->p_filesz);
			if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
				z_errx(1, "can't lseek interp segment");
			if (z_read(fd, elf_interp, iter->p_filesz) !=
					(ssize_t)iter->p_filesz)
				z_errx(1, "can't read interp segment");
			if (elf_interp[iter->p_filesz - 1] != '\0')
				z_errx(1, "bogus interp path");
			if (child_loader && child_proto.exec_interp) {
				/* Payload resolved it with guest symlink semantics and the
				 * read policy; never re-map the raw PT_INTERP here. */
				file = child_proto.exec_interp;
			} else {
#ifdef FD_EXPERIMENT
				/* A target swapped after the payload's check must not fall
				 * back to lexical host mapping and bypass the read policy. */
				if (child_loader && bootstrap_cfg.guard_file_reads)
					z_errx(1, "interpreter not authorized by payload");
#endif
				/* Resolve interpreter inside configured root/binds to avoid host escape */
				file = rewrite_interp_path(&bootstrap_cfg, elf_interp,
							   interp_path, sizeof(interp_path));
			}
			z_printf("[Loader] interp \"%s\" -> \"%s\"\n", elf_interp, file);
			load_interp_next = 1;
			break;
		}

		z_close(fd);
		if (!load_interp_next)
			break;
	}

	/* fexecve: the program is loaded; its descriptor copy is not the guest's. */
	if (child_loader && child_proto.exec_fd > 2)
		z_close(child_proto.exec_fd);

	const char *execfn = bootstrap_cfg.use_init ? file : target_argv[0];
	if (child_loader && child_exec_path)
		execfn = child_exec_path;
	if (shell_mode)
		execfn = target_argv[0];
	if (shebang_mode && shebang_script[0] && !child_exec_path)
		execfn = shebang_script;

	int saw_execfn = 0;

#define AVSET(t, v, expr) case (t): (v)->a_un.a_val = (expr); break
	while (av->a_type != AT_NULL) {
		switch (av->a_type) {
		AVSET(AT_PHDR, av, base[Z_PROG] + ehdrs[Z_PROG].e_phoff);
		AVSET(AT_PHNUM, av, ehdrs[Z_PROG].e_phnum);
		AVSET(AT_PHENT, av, ehdrs[Z_PROG].e_phentsize);
		AVSET(AT_ENTRY, av, entry[Z_PROG]);
		case AT_EXECFN:
			av->a_un.a_val = (unsigned long)execfn;
			saw_execfn = 1;
			z_printf("[Loader] AT_EXECFN=%p \"%s\"\n",
				 (void *)execfn, execfn ? execfn : "(null)");
			break;
		AVSET(AT_BASE, av, elf_interp ?
				base[Z_INTERP] : 0);
		}
		++av;
	}
#undef AVSET
#ifdef PROOT_PATH
    /* Snapshot the rewritten guest vector BEFORE argv/env stack compaction.
     * Pointer-valued entries refer to guest mappings or preserved stack strings.
     * Each loader exec constructs a fresh snapshot; never read kernel loader auxv. */
    if (payload_cfg) {
        size_t pairs = (size_t)(av - av_start) + 1;
        if (pairs > CONFIG_AUXV_PAIRS)
            z_errx(1, "guest auxv exceeds payload capacity");
        z_memcpy(payload_cfg->guest_auxv, av_start, pairs * sizeof(*av_start));
        payload_cfg->guest_auxv_bytes = pairs * sizeof(*av_start);
        /* The loader image (code, data, the SIGSYS handler's state) and the
         * islands for the initial images are protected from guest mm calls. */
        {
            extern uint64_t g_loader_islands[64][2];
            extern unsigned g_loader_island_count;
            extern char __ehdr_start[], _end[];
            unsigned n = 0;
            payload_cfg->protected_ranges[n][0] = (uint64_t)__ehdr_start;
            payload_cfg->protected_ranges[n++][1] = ((uint64_t)_end + 4095) & ~4095ul;
            for (unsigned i = 0; i < g_loader_island_count && n < 64; i++, n++) {
                payload_cfg->protected_ranges[n][0] = g_loader_islands[i][0];
                payload_cfg->protected_ranges[n][1] = g_loader_islands[i][1];
            }
            payload_cfg->protected_count = n;
        }
    }
#endif
	if (!saw_execfn)
		z_printf("[Loader] AT_EXECFN not present in auxv\n");
	++av;

	if (shebang_mode) {
		int envc = final_envc;

		int auxc = 0;
		Elf_auxv_t *aux_src = av_start;
		while (aux_src[auxc].a_type != AT_NULL)
			auxc++;
		auxc++; /* include AT_NULL */

		/* Build argv list: interp [arg] script_path <script args> */
		int orig_target_argc = argc - argi; /* includes script + its args */
		int extra = 1; /* script path */
		if (shebang_interp_arg[0])
			extra++;
		int new_argc = orig_target_argc + extra;

		char **dst = argv;
		int pos = 0;
		dst[pos++] = shebang_interp;
		if (shebang_interp_arg[0])
			dst[pos++] = shebang_interp_arg;
		dst[pos++] = shebang_script;
		for (int k = 1; k < orig_target_argc; k++)
			dst[pos++] = argv[argi + k];
		dst[new_argc] = NULL;

		char **dst_env = &dst[new_argc + 1];
		for (int e = 0; e < envc; e++)
			dst_env[e] = final_env_ptrs[e];
		dst_env[envc] = NULL;

		Elf_auxv_t *dst_aux = (Elf_auxv_t *)&dst_env[envc + 1];
		for (int a = 0; a < auxc; a++)
			dst_aux[a] = aux_src[a];

		*sp = new_argc;
	} else {
		int envc = final_envc;

		int auxc = 0;
		Elf_auxv_t *aux_src = av_start;
		while (aux_src[auxc].a_type != AT_NULL)
			auxc++;
		auxc++;

		int user_argc = argc - argi;
		if (user_argc < 0)
			user_argc = 0;
		int extra = (bootstrap_cfg.use_init && !shell_mode) ? 1 : 0;
		int new_argc = user_argc + extra;
		char **dst = argv;
		int pos = 0;
		if (shell_mode) {
			for (int k = 0; target_argv[k]; k++)
				dst[pos++] = target_argv[k];
			new_argc = pos;
		} else {
			if (bootstrap_cfg.use_init)
				dst[pos++] = (char *)file;
			for (int k = 0; k < user_argc; k++)
				dst[pos++] = argv[argi + k];
		}
		dst[new_argc] = NULL;

		char **dst_env = &dst[new_argc + 1];
		for (int e = 0; e < envc; e++)
			dst_env[e] = final_env_ptrs[e];
		dst_env[envc] = NULL;

		Elf_auxv_t *dst_aux = (Elf_auxv_t *)&dst_env[envc + 1];
		for (int a = 0; a < auxc; a++)
			dst_aux[a] = aux_src[a];

		*sp = new_argc;
	}

	if (install_guest_debugger() < 0)
		z_printf("[Debugger] SIGSEGV debugger setup failed, continuing without it\n");
#if defined(PROOT_PATH) && defined(__aarch64__)
	if (bootstrap_cfg.seccomp_backstop) {
		g_payload_entry = payload_entry_addr;
		if (g_payload_lo != PAYLOAD_FIXED_BASE)
			z_errx(1, "seccomp backstop: payload not at its fixed address");
		if (backstop_handler() < 0)
			z_errx(1, "seccomp backstop: cannot install SIGSYS handler");
		/* Installed once; it survives exec into every child loader. */
		if (!child_loader && backstop_filter() < 0)
			z_errx(1, "seccomp backstop: cannot install the filter (errno %d)", z_errno);
	}
#endif

#ifdef PROOT_PATH
	/* /proc/<pid>/{comm,stat,status} name the guest program, not the loader
	 * (the kernel derives comm from the exec'd loader file). */
	if (child_proto.exec_name || bootstrap_cfg.exec_exe[0]) {
		const char *base = child_proto.exec_name ? child_proto.exec_name : bootstrap_cfg.exec_exe;
		for (const char *p = base; *p; p++)
			if (*p == '/' && p[1]) base = p + 1;
		z_prctl(15 /* PR_SET_NAME */, (unsigned long)base, 0);
	}
#endif
	z_trampo((void (*)(void))(elf_interp ?
			entry[Z_INTERP] : entry[Z_PROG]), sp, z_fini);
	z_exit(0);
}
