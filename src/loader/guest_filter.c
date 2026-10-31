/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolation mode: the guest filter (docs/ISOLATION.md). Installed by the
 * initial loader right before the program starts and inherited by every
 * guest process; the broker forked earlier stays outside it. Every call
 * that names a file, changes file metadata through an FD, or reaches past
 * the broker into other processes fails with EPERM, whatever address it
 * comes from: the payload asks the broker instead.
 *
 * With --isolate-device the guest opens the selected devices itself (their
 * drivers bind a context to the opener's address space): openat is allowed
 * for the device path constants of the loader's constant page only, and the
 * filter keeps that page in place and every guest process on the loader
 * image (docs/ISOLATION.md, "GPU 设备"). Without it the program is the same
 * as before, instruction for instruction (test/isolation/device.py). */
#include <asm/unistd.h>
#include "loader.h"

#define AUDIT_ARCH_AARCH64 0xc00000b7u
#define RET_KILL_PROCESS   0x80000000u
#define RET_ERRNO_EPERM    (0x00050000u | 1)
#define RET_ALLOW          0x7fff0000u
#define AF_UNIX_           1
#define SOCK_DGRAM_        2
/* openat flags a device open may carry (no O_CREAT, O_PATH, O_TMPFILE,
 * O_TRUNC, O_DIRECTORY): O_ACCMODE, O_NOCTTY, O_NONBLOCK, O_LARGEFILE
 * (AArch64 value), O_CLOEXEC. */
#define DEVICE_OPEN_FLAGS  (03u | 0400u | 04000u | 0400000u | 02000000u)
#define FIOCLEX_           0x5451u
#define F_SETFD_           2u
#define MAP_FIXED_         0x10u
#define MREMAP_FIXED_      2u
#define SHM_REMAP_         040000u

/* Refused outright (AArch64 numbers). */
static const unsigned short denied[] = {
	/* Calls on paths. */
	56,  /* openat */
	437, /* openat2 */
	264, /* name_to_handle_at */
	265, /* open_by_handle_at */
	79,  /* newfstatat */
	291, /* statx */
	48,  /* faccessat */
	439, /* faccessat2 */
	78,  /* readlinkat */
	34,  /* mkdirat */
	33,  /* mknodat */
	35,  /* unlinkat */
	36,  /* symlinkat */
	37,  /* linkat */
	38,  /* renameat */
	276, /* renameat2 */
	53,  /* fchmodat */
	452, /* fchmodat2 */
	54,  /* fchownat */
	88,  /* utimensat (with a NULL path an FD call: the broker checks it) */
	45,  /* truncate */
	43,  /* statfs */
	49,  /* chdir */
	51,  /* chroot */
	5, 6, 8, 9, 11, 12, 14, 15, /* path xattr calls */
	463, 464, 465, 466, /* *xattrat (Linux 6.13) */
	468, 469, /* file_getattr, file_setattr (Linux 6.17) */
	27,  /* inotify_add_watch */
	263, /* fanotify_mark */
	89,  /* acct */
	224, 225, /* swapon, swapoff */
	60,  /* quotactl */
	221, /* execve (exec is execveat on an FD, below) */
	/* Metadata changes through an FD. */
	52,  /* fchmod */
	55,  /* fchown */
	7,   /* fsetxattr */
	16,  /* fremovexattr */
	/* Socket names are host paths the filter cannot see. */
	200, /* bind */
	203, /* connect */
	/* Past the broker, or into other processes. */
	425, 426, 427, /* io_uring */
	270, 271, /* process_vm_readv, process_vm_writev */
	440, /* process_madvise */
	438, /* pidfd_getfd */
	117, /* ptrace */
	272, /* kcmp */
	280, /* bpf */
	241, /* perf_event_open */
	40, 39, 41, /* mount, umount2, pivot_root */
	428, 429, 430, 431, 432, 433, 442, 467, /* new mount API, open_tree_attr */
};

/* ioctl requests that change inode attributes. */
static const unsigned int denied_ioctls[] = {
	0x40086602u, /* FS_IOC_SETFLAGS */
	0x40087602u, /* FS_IOC_SETVERSION */
	0x401c5820u, /* FS_IOC_FSSETXATTR */
	0x41009432u, /* FS_IOC_SETFSLABEL */
	0x800c6613u, /* FS_IOC_SET_ENCRYPTION_POLICY */
};

enum { L_NEXT = -1, L_ALLOW = -2, L_DENY = -3, L_EXECVEAT = -4, L_SOCKET = -5,
       L_SOCKETPAIR = -6, L_PRLIMIT = -7, L_IOCTL = -8 };
#define LABELS 9
#define LABELS_MAX 128
#define PROG_MAX 1024

struct insn {
	unsigned short code;
	int jt, jf; /* labels until resolved */
	unsigned int k; /* a label for JA */
};
static struct insn prog[PROG_MAX];
static int count, label_at[LABELS_MAX], labels;
static struct { unsigned short code; unsigned char jt, jf; unsigned int k; } filter[PROG_MAX];

static void emit(unsigned short code, int jt, int jf, unsigned int k)
{
	if (count == PROG_MAX)
		z_errx(1, "isolate: guest filter too long");
	prog[count++] = (struct insn){code, jt, jf, k};
}
static int new_label(void)
{
	if (labels == LABELS_MAX)
		z_errx(1, "isolate: guest filter has too many labels");
	return -labels++;
}
static void label(int l) { label_at[-l] = count; }
#define LD(off)          emit(0x20, 0, 0, (off))       /* ld [off] */
#define LDI(v)           emit(0x00, 0, 0, (v))         /* ld #v */
#define LDXM(m)          emit(0x61, 0, 0, (m))         /* ldx M[m] */
#define ST(m)            emit(0x02, 0, 0, (m))         /* st M[m] */
#define TAX()            emit(0x07, 0, 0, 0)
#define SUBX()           emit(0x1c, 0, 0, 0)
#define SUBK(v)          emit(0x14, 0, 0, (v))
#define JEQ(v, t, f)     emit(0x15, (t), (f), (v))
#define JGT(v, t, f)     emit(0x25, (t), (f), (v))
#define JGE(v, t, f)     emit(0x35, (t), (f), (v))
#define JSET(v, t, f)    emit(0x45, (t), (f), (v))
#define JEQX(t, f)       emit(0x1d, (t), (f), 0)
#define JGTX(t, f)       emit(0x2d, (t), (f), 0)
#define JA(l)            emit(0x05, 0, 0, (unsigned int)(l))
#define AND(v)           emit(0x54, 0, 0, (v))
#define RET(v)           emit(0x06, 0, 0, (v))
/* seccomp_data: nr 0, arch 4, ip 8, args from 16 (low word first). */
#define NR      0
#define ARCH    4
#define ARG(i)  (16 + 8 * (i))
#define ARGHI(i) (20 + 8 * (i))
#define LO(v)   ((unsigned int)(uint64_t)(v))
#define HI(v)   ((unsigned int)((uint64_t)(v) >> 32))

/* Each device section ends in its own returns: the base program's are
 * behind them, classic BPF only jumps forward, and a conditional jump
 * reaches 255 instructions. */
static int d_allow, d_deny, far_deny;

static void section(int l)
{
	label(l);
	d_allow = new_label();
	d_deny = new_label();
}

static void section_end(void)
{
	label(d_allow);
	RET(RET_ALLOW);
	label(d_deny);
	RET(RET_ERRNO_EPERM);
}

/* Jumps to `yes` when [arg a, arg a + arg l) meets the constant page
 * [g0, g1), else to `no` (64-bit compares on 32-bit halves; an address
 * range that wraps is refused by the kernel anyway). */
static void meets_page(int a, int l, int yes, int no)
{
	uint64_t g0 = (uint64_t)&g_isolate_page, g1 = g0 + sizeof(g_isolate_page);
	int below_end = new_label(), below_start = new_label(), check_lo = new_label();
	int borrow = new_label(), compare = new_label();
	/* a < g1, else no. */
	LD(ARGHI(a));
	JGT(HI(g1), no, L_NEXT);
	JEQ(HI(g1), L_NEXT, below_end);
	LD(ARG(a));
	JGE(LO(g1), no, below_end);
	label(below_end);
	/* a >= g0: inside. */
	LD(ARGHI(a));
	JGT(HI(g0), yes, L_NEXT);
	JEQ(HI(g0), L_NEXT, below_start);
	LD(ARG(a));
	JGE(LO(g0), yes, below_start);
	/* a < g0: meets when l > g0 - a (M[1]:M[0]). */
	label(below_start);
	LD(ARG(a));
	TAX();
	LDI(LO(g0));
	SUBX();
	ST(0);
	LD(ARG(a));
	JGT(LO(g0), borrow, L_NEXT);
	LD(ARGHI(a));
	TAX();
	LDI(HI(g0));
	SUBX();
	ST(1);
	JA(compare);
	label(borrow);
	LD(ARGHI(a));
	TAX();
	LDI(HI(g0));
	SUBX();
	SUBK(1);
	ST(1);
	label(compare);
	LDXM(1);
	LD(ARGHI(l));
	JGTX(yes, L_NEXT);
	JEQX(check_lo, no);
	label(check_lo);
	LDXM(0);
	LD(ARG(l));
	JGTX(yes, no);
}

/* nr goes to a device section (a far jump: the base list lies between). */
static void dispatch(unsigned nr, int section)
{
	JEQ(nr, 0, 1);
	JA(section);
}

static void build(uint32_t mask)
{
	count = 0;
	labels = LABELS;
	int sections[16], n = 0;
	static const unsigned short device_calls[] = {
		56,  /* openat */
		281, /* execveat */
		57,  /* close */
		436, /* close_range */
		24,  /* dup3 */
		25,  /* fcntl */
		29,  /* ioctl */
		215, /* munmap */
		226, /* mprotect */
		288, /* pkey_mprotect */
		233, /* madvise */
		234, /* remap_file_pages */
		222, /* mmap */
		216, /* mremap */
		196, /* shmat */
		282, /* userfaultfd; unshare and setns below */
	};
	LD(ARCH);
	JEQ(AUDIT_ARCH_AARCH64, 1, 0);
	RET(RET_KILL_PROCESS);
	LD(NR);
	if (mask) {
		far_deny = new_label();
		for (unsigned i = 0; i < sizeof(device_calls) / sizeof(device_calls[0]); i++) {
			sections[n] = new_label();
			dispatch(device_calls[i], sections[n++]);
		}
		/* Namespaces could change what a device path names (the host
		 * sandbox refuses them too). */
		dispatch(97 /* unshare */, far_deny);
		dispatch(268 /* setns */, far_deny);
	}
	for (unsigned i = 0; i < sizeof(denied) / sizeof(denied[0]); i++)
		JEQ(denied[i], L_DENY, L_NEXT);
	JEQ(281 /* execveat */, L_EXECVEAT, L_NEXT);
	JEQ(198 /* socket */, L_SOCKET, L_NEXT);
	JEQ(199 /* socketpair */, L_SOCKETPAIR, L_NEXT);
	JEQ(261 /* prlimit64 */, L_PRLIMIT, L_NEXT);
	JEQ(29 /* ioctl */, L_IOCTL, L_NEXT);
	RET(RET_ALLOW);

	/* Only an FD runs: the path must be empty (unchecked here, see
	 * docs/ISOLATION.md, residual risks). */
	label(L_EXECVEAT);
	LD(ARG(4));
	JSET(AT_EMPTY_PATH, L_ALLOW, L_DENY);
	/* UNIX sockets come from the broker; unnamed pairs only as streams or
	 * sequenced packets (a datagram may be sent to any name). */
	label(L_SOCKET);
	LD(ARG(0));
	JEQ(AF_UNIX_, L_DENY, L_ALLOW);
	label(L_SOCKETPAIR);
	LD(ARG(0));
	JEQ(AF_UNIX_, L_NEXT, L_ALLOW);
	LD(ARG(1));
	AND(0xf);
	JEQ(SOCK_DGRAM_, L_DENY, L_ALLOW);
	/* Own limits only (pid 0). */
	label(L_PRLIMIT);
	LD(ARG(0));
	JEQ(0, L_NEXT, L_DENY);
	LD(ARGHI(0));
	JEQ(0, L_ALLOW, L_DENY);
	label(L_IOCTL);
	LD(ARG(1));
	for (unsigned i = 0; i < sizeof(denied_ioctls) / sizeof(denied_ioctls[0]); i++)
		JEQ(denied_ioctls[i], L_DENY, L_NEXT);
	label(L_ALLOW);
	RET(RET_ALLOW);
	label(L_DENY);
	RET(RET_ERRNO_EPERM);
	if (!mask)
		return;

	const unsigned loader_fd = CONFIG_ISOLATE_LOADER_FD;
	int s = 0;
	/* openat: a selected device constant, absolute (dirfd unused), with
	 * plain open flags. */
	section(sections[s++]);
	LD(ARG(2));
	AND(~DEVICE_OPEN_FLAGS);
	JEQ(0, L_NEXT, d_deny);
	for (int i = 0; i < ISOLATE_DEVICES; i++) {
		if (!(mask & (1u << i)))
			continue;
		uint64_t p = (uint64_t)g_isolate_page.table.path[i];
		int other = new_label();
		LD(ARG(1));
		JEQ(LO(p), L_NEXT, other);
		LD(ARGHI(1));
		JEQ(HI(p), d_allow, other);
		label(other);
	}
	JA(d_deny);
	section_end();
	/* execveat: only the loader FD, with the page's empty path: every
	 * filtered process runs the loader image. */
	section(sections[s++]);
	{
		uint64_t e = (uint64_t)g_isolate_page.table.empty;
		LD(ARG(0));
		JEQ(loader_fd, L_NEXT, d_deny);
		LD(ARG(1));
		JEQ(LO(e), L_NEXT, d_deny);
		LD(ARGHI(1));
		JEQ(HI(e), L_NEXT, d_deny);
		LD(ARG(4));
		JSET(AT_EMPTY_PATH, d_allow, d_deny);
	}
	section_end();
	/* The loader FD stays: close, close_range over it, dup3 onto it,
	 * F_SETFD and FIOCLEX on it. FD arguments are unsigned int to the
	 * kernel, so the low word is the whole number. */
	section(sections[s++]); /* close */
	LD(ARG(0));
	JEQ(loader_fd, d_deny, d_allow);
	section_end();
	section(sections[s++]); /* close_range */
	LD(ARG(0));
	JGT(loader_fd, d_allow, L_NEXT);
	LD(ARG(1));
	JGE(loader_fd, d_deny, d_allow);
	section_end();
	section(sections[s++]); /* dup3 */
	LD(ARG(1));
	JEQ(loader_fd, d_deny, d_allow);
	section_end();
	section(sections[s++]); /* fcntl */
	LD(ARG(0));
	JEQ(loader_fd, L_NEXT, d_allow);
	LD(ARG(1));
	JEQ(F_SETFD_, d_deny, d_allow);
	section_end();
	section(sections[s++]); /* ioctl: as the base list, and FIOCLEX on it */
	{
		int request = new_label();
		LD(ARG(0));
		JEQ(loader_fd, L_NEXT, request);
		LD(ARG(1));
		JEQ(FIOCLEX_, d_deny, request);
		label(request);
		LD(ARG(1));
		for (unsigned i = 0; i < sizeof(denied_ioctls) / sizeof(denied_ioctls[0]); i++)
			JEQ(denied_ioctls[i], d_deny, L_NEXT);
		JA(d_allow);
	}
	section_end();
	/* The constant page stays mapped, read-only, and file backed. */
	for (int i = 0; i < 5; i++) { /* munmap .. remap_file_pages: (addr, len) */
		section(sections[s++]);
		meets_page(0, 1, d_deny, d_allow);
		section_end();
	}
	section(sections[s++]); /* mmap: MAP_FIXED replaces what it meets */
	{
		int fixed = new_label();
		LD(ARG(3));
		JSET(MAP_FIXED_, fixed, d_allow);
		label(fixed);
		meets_page(0, 1, d_deny, d_allow);
	}
	section_end();
	section(sections[s++]); /* mremap: the old range, and a fixed new one */
	{
		int old_clear = new_label(), fixed = new_label();
		meets_page(0, 1, d_deny, old_clear);
		label(old_clear);
		LD(ARG(3));
		JSET(MREMAP_FIXED_, fixed, d_allow);
		label(fixed);
		meets_page(4, 2, d_deny, d_allow);
	}
	section_end();
	section(sections[s++]); /* shmat: SHM_REMAP replaces what it meets */
	LD(ARG(2));
	JSET(SHM_REMAP_, d_deny, d_allow);
	section_end();
	section(sections[s++]); /* userfaultfd */
	JA(d_deny);
	section_end();
	if (s != n)
		z_errx(1, "isolate: guest filter sections");
	label(far_deny);
	RET(RET_ERRNO_EPERM);
}

/* Labels to offsets. */
static void resolve_jumps(void)
{
	for (int i = 0; i < count; i++) {
		if (prog[i].code == 0x05) {
			int target = label_at[-(int)prog[i].k];
			if (target <= i)
				z_errx(1, "isolate: guest filter jump backwards");
			filter[i] = (typeof(filter[i])){0x05, 0, 0, (unsigned)(target - (i + 1))};
			continue;
		}
		int t[2] = {prog[i].jt, prog[i].jf};
		for (int j = 0; j < 2; j++) {
			int target = t[j] == L_NEXT ? i + 1 : t[j] < 0 ? label_at[-t[j]] : i + 1 + t[j];
			int offset = target - (i + 1);
			if (offset < 0 || offset > 255)
				z_errx(1, "isolate: guest filter jump out of range");
			t[j] = offset;
		}
		filter[i].code = prog[i].code;
		filter[i].jt = (unsigned char)t[0];
		filter[i].jf = (unsigned char)t[1];
		filter[i].k = prog[i].k;
	}
}

void guest_filter_install(uint32_t device_mask)
{
	build(device_mask);
	resolve_jumps();
	struct { unsigned short len; void *filter; } fprog = {(unsigned short)count, filter};
	if (z_syscall(__NR_prctl, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0) < 0 ||
	    z_syscall(__NR_seccomp, 1 /* SECCOMP_SET_MODE_FILTER */, 0, &fprog) < 0)
		z_errx(1, "isolate: cannot install the guest filter");
}

/* --guest-filter-dump: one "code jt jf k" line (hex) per instruction, then
 * the constant page's addresses, for tests. */
void guest_filter_dump(uint32_t device_mask)
{
	build(device_mask);
	resolve_jumps();
	for (int i = 0; i < count; i++)
		z_fdprintf(1, "%x %x %x %x\n", filter[i].code, filter[i].jt, filter[i].jf, filter[i].k);
	z_fdprintf(1, "page %lx %lx\n", (unsigned long)&g_isolate_page,
		 (unsigned long)&g_isolate_page + sizeof(g_isolate_page));
}
