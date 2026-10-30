#ifndef SYSCALL_NUMS_H
#define SYSCALL_NUMS_H

/* Prefer target AArch64 ABI headers (also in .S); explicitly supplement guest
 * calls missing from older host headers below. */
#include <asm/unistd.h>
/* Older host headers omit this AArch64 entry. Ubuntu guest libc's fchmodat
 * wrapper emits syscall 452 when flags are present. Keep it interceptable. */
#ifndef __NR_fchmodat2
#define __NR_fchmodat2 452
#endif
/* Path-taking calls newer than the target headers (Linux 6.13-6.17). The
 * backends do not translate them, and a raw pass would resolve guest paths
 * on the host: they are routed slowly and refused with ENOSYS, as an older
 * kernel would, so libc and programs fall back to the translated calls. */
#ifndef __NR_setxattrat
#define __NR_setxattrat 463
#endif
#ifndef __NR_getxattrat
#define __NR_getxattrat 464
#endif
#ifndef __NR_listxattrat
#define __NR_listxattrat 465
#endif
#ifndef __NR_removexattrat
#define __NR_removexattrat 466
#endif
#ifndef __NR_open_tree_attr
#define __NR_open_tree_attr 467
#endif
#ifndef __NR_file_getattr
#define __NR_file_getattr 468
#endif
#ifndef __NR_file_setattr
#define __NR_file_setattr 469
#endif
#endif /* SYSCALL_NUMS_H */
