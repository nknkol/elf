/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolation mode: the guest filter (docs/ISOLATION.md). Installed by the
 * initial loader right before the program starts and inherited by every
 * guest process; the broker forked earlier stays outside it. Every call
 * that names a file, changes file metadata through an FD, or reaches past
 * the broker into other processes fails with EPERM, whatever address it
 * comes from: the payload asks the broker instead. */
#include <asm/unistd.h>
#include "loader.h"

#define AUDIT_ARCH_AARCH64 0xc00000b7u
#define RET_KILL_PROCESS   0x80000000u
#define RET_ERRNO_EPERM    (0x00050000u | 1)
#define RET_ALLOW          0x7fff0000u
#define AF_UNIX_           1
#define SOCK_DGRAM_        2

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

struct insn {
	unsigned short code;
	int jt, jf; /* labels until resolved */
	unsigned int k;
};
static struct insn prog[160];
static int count, label_at[LABELS];

static void emit(unsigned short code, int jt, int jf, unsigned int k)
{
	if (count == (int)(sizeof(prog) / sizeof(prog[0])))
		z_errx(1, "isolate: guest filter too long");
	prog[count++] = (struct insn){code, jt, jf, k};
}
static void label(int l) { label_at[-l] = count; }
#define LD(off)          emit(0x20, 0, 0, (off))       /* ld [off] */
#define JEQ(v, t, f)     emit(0x15, (t), (f), (v))
#define JSET(v, t, f)    emit(0x45, (t), (f), (v))
#define AND(v)           emit(0x54, 0, 0, (v))
#define RET(v)           emit(0x06, 0, 0, (v))
/* seccomp_data: nr 0, arch 4, ip 8, args from 16 (low word first). */
#define NR      0
#define ARCH    4
#define ARG(i)  (16 + 8 * (i))
#define ARGHI(i) (20 + 8 * (i))

void guest_filter_install(void)
{
	count = 0;
	LD(ARCH);
	JEQ(AUDIT_ARCH_AARCH64, 1, 0);
	RET(RET_KILL_PROCESS);
	LD(NR);
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

	struct { unsigned short code; unsigned char jt, jf; unsigned int k; } f[160];
	for (int i = 0; i < count; i++) {
		int t[2] = {prog[i].jt, prog[i].jf};
		for (int j = 0; j < 2; j++) {
			int target = t[j] == L_NEXT ? i + 1 : t[j] < 0 ? label_at[-t[j]] : i + 1 + t[j];
			int offset = target - (i + 1);
			if (offset < 0 || offset > 255)
				z_errx(1, "isolate: guest filter jump out of range");
			t[j] = offset;
		}
		f[i].code = prog[i].code;
		f[i].jt = (unsigned char)t[0];
		f[i].jf = (unsigned char)t[1];
		f[i].k = prog[i].k;
	}
	struct { unsigned short len; void *filter; } fprog = {(unsigned short)count, f};
	if (z_syscall(__NR_prctl, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0) < 0 ||
	    z_syscall(__NR_seccomp, 1 /* SECCOMP_SET_MODE_FILTER */, 0, &fprog) < 0)
		z_errx(1, "isolate: cannot install the guest filter");
}
