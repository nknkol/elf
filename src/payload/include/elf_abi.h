/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Fixed numbers shared by the loader, the payload and the tests. */
#ifndef ELF_ABI_H
#define ELF_ABI_H

/* Layout of payload_config_t and the stub contract; the loader refuses a
 * payload with another version. */
#define PAYLOAD_ABI_VERSION 16

/* Fixed addresses: the seccomp backstop allows syscalls by address. */
#define LOADER_FIXED_BASE  0x3f00000000ul
#define PAYLOAD_FIXED_BASE 0x3f80000000ul

/* Linux 6.4 prctl, served from the guest's auxv. */
#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif
/* Diagnostics of the guarded runtime's FD records ("FDTR"). */
#define PR_ELF_FD_QUERY 0x46445452
/* HarmonyOS: prctl(PR_HM_JIT, 0, 0) lets the next mprotect make anonymous
 * memory executable; prctl(PR_HM_JIT, 0, 1) closes that window again. */
#define PR_HM_JIT 0x6a6974

/* SECCOMP_RET_TRAP data of the backstop filter (si_errno), telling its
 * traps from those of the host sandbox's own filter. */
#define BACKSTOP_TRAP_DATA 0x0e1f

#endif
