/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <asm/unistd.h>
#include <ucontext.h>
#include "loader.h"
#include "elf_abi.h"

/* --seccomp-backstop: a seccomp filter traps every syscall that does not
 * come from the loader image or the payload (both at fixed addresses, so
 * the filter, which survives exec, stays valid in every descendant). The
 * SIGSYS handler forwards the trapped call into the payload exactly as a
 * stub would, so unhooked svc (JIT code, unreachable sites, the vDSO
 * fallback) still gets guest semantics. rt_sigreturn, exit, exit_group,
 * restart_syscall and clone are allowed by number: they take no paths and
 * clone cannot run inside a signal handler. */
static unsigned long g_payload_entry;
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

static void loader_sigsys_handler(int sig, siginfo_t *si, void *ucontext)
{
	ucontext_t *uc = (ucontext_t *)ucontext;
	/* Our TRAP action's data comes in si_errno: the host sandbox's own
	 * filter traps some calls too, and those keep their native effect. */
	if (!si || si->si_code != 1 /* SYS_SECCOMP */ || si->si_errno != BACKSTOP_TRAP_DATA || !uc) {
		die_of_signal(sig);
		return;
	}
	unsigned long *regs = (unsigned long *)uc->uc_mcontext.regs;
	regs[0] = (unsigned long)backstop_call(g_payload_entry, regs);
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
	return z_syscall(__NR_seccomp, 1 /* SECCOMP_SET_MODE_FILTER */, 0, &prog) < 0 ? -1 : 0;
}

/* The filter survives exec, so only the initial loader installs it; every
 * loader installs the handler. */
void backstop_install(unsigned long payload_entry, int with_filter)
{
	g_payload_entry = payload_entry;
	if (g_payload_lo != PAYLOAD_FIXED_BASE)
		z_errx(1, "seccomp backstop: payload not at its fixed address");
	/* NODEFER: a guest handler run from here may itself trap. */
	if (signal_install(SIGSYS, loader_sigsys_handler, SA_SIGINFO | SA_ONSTACK | SA_NODEFER) < 0)
		z_errx(1, "seccomp backstop: cannot install SIGSYS handler");
	if (with_filter && backstop_filter() < 0)
		z_errx(1, "seccomp backstop: cannot install the filter");
}

