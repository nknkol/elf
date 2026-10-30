#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include "syscall_nums.h"
#include "syscall_hooks.h"
#include "hook_runtime.h"
#include "config.h"
#ifdef PROOT_PATH
#include "proot_bridge.h"
#include "fake_ids.h"
#endif
#ifdef FD_EXPERIMENT
#include "fd_experiment.h"
#endif

typedef struct {
    unsigned long regs[30]; // x0 - x29
    unsigned long lr;       // x30
    unsigned long _pad;
} pt_regs;

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

/* getuid and friends report root (PRoot -0). Keep stat consistent with
 * that: the caller's own files read as owned by uid/gid 0. "Own" is the real
 * uid/gid plus the owners of the configured root and bind host directories;
 * some backings (HarmonyOS shared storage) give the caller's files a service
 * owner instead of its uid. Other owners stay as they are. Applied to the
 * guest's output buffer after kernel success. */
#define OWNERS (CONFIG_MAX_BINDS + 2)
static unsigned owner_uid[OWNERS], owner_gid[OWNERS];
static int owner_count, owner_state; /* 0 none, 1 building, 2 published */
static void collect_owners(void)
{
    int expected = 0;
    if (!__atomic_compare_exchange_n(&owner_state, &expected, 1, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return;
    int n = 0;
    owner_uid[n] = (unsigned)raw_syscall(__NR_getuid, 0, 0, 0, 0, 0, 0);
    owner_gid[n++] = (unsigned)raw_syscall(__NR_getgid, 0, 0, 0, 0, 0, 0);
    for (int i = -1; i < g_payload_config.bind_count && i < CONFIG_MAX_BINDS; i++) {
        const char *host = i < 0 ? g_payload_config.root : g_payload_config.binds[i].dst;
        struct { unsigned char data[128]; } st;
        if (!host[0] || raw_syscall(__NR_newfstatat, -100, (long)host, (long)&st, 0, 0, 0) < 0)
            continue;
        if ((*(unsigned *)(st.data + 16) & 0170000) != 0040000) continue;
        owner_uid[n] = *(unsigned *)(st.data + 24);
        owner_gid[n++] = *(unsigned *)(st.data + 28);
    }
    owner_count = n;
    __atomic_store_n(&owner_state, 2, __ATOMIC_RELEASE);
}
#ifdef PROOT_PATH
uint32_t fake_reported_owner(uint32_t id, int group)
{
    collect_owners();
    if (__atomic_load_n(&owner_state, __ATOMIC_ACQUIRE) != 2) return id;
    for (int i = 0; i < owner_count; i++)
        if (id == (group ? owner_gid[i] : owner_uid[i])) return fake_ids_owner(group);
    return id;
}
#endif
static void fake_owner(long sys_no, const long *a)
{
    unsigned char *buffer;
    unsigned uid_offset;
    if (sys_no == __NR_fstat) { buffer = (void *)a[1]; uid_offset = 24; }
    else if (sys_no == __NR_newfstatat) { buffer = (void *)a[2]; uid_offset = 24; }
    else if (sys_no == __NR_statx) { buffer = (void *)a[4]; uid_offset = 20; }
    else return;
    if (!buffer) return;
    collect_owners();
    /* A concurrent first caller may still be building: leave this result. */
    if (__atomic_load_n(&owner_state, __ATOMIC_ACQUIRE) != 2) return;
    unsigned *owner = (unsigned *)(buffer + uid_offset);
    int uid_hit = 0, gid_hit = 0;
    for (int i = 0; i < owner_count; i++) {
        uid_hit |= owner[0] == owner_uid[i];
        gid_hit |= owner[1] == owner_gid[i];
    }
#ifdef PROOT_PATH
    /* The caller's own files belong to its fake saved ids, as in PRoot. */
    if (uid_hit) owner[0] = fake_ids_owner(0);
    if (gid_hit) owner[1] = fake_ids_owner(1);
#else
    if (uid_hit) owner[0] = 0;
    if (gid_hit) owner[1] = 0;
#endif
}

#ifdef PROOT_PATH
/* --seccomp-backstop: the loader's SIGSYS handler must stay installed. A
 * guest's own SIGSYS action is recorded and reported back, never installed
 * (signals the guest raises itself are then not delivered to it). */
static unsigned char guest_sigsys[32];
static long backstop_sigaction(long *a)
{
    if (a[3] != 8) return -EINVAL;
    unsigned char previous[32];
    memcpy(previous, guest_sigsys, sizeof(previous));
    if (a[1]) memcpy(guest_sigsys, (const void *)a[1], sizeof(guest_sigsys));
    if (a[2]) memcpy((void *)a[2], previous, sizeof(previous));
    return 0;
}
#endif

long syscall_dispatcher(long sys_no, pt_regs *regs)
{
    long *a = (long *)regs->regs;
    long args[6];

    /* Copy original args to a scratch array so we don't mutate saved regs */
    args[0] = a[0];
    args[1] = a[1];
    args[2] = a[2];
    args[3] = a[3];
    args[4] = a[4];
    args[5] = a[5];

    if (sys_no >= __NR_setxattrat && sys_no <= __NR_file_setattr)
        return -ENOSYS; /* Untranslated newer path calls (syscall_nums.h). */
    /* Loader, payload and stub islands are sealed against the guest's own
     * mm calls (EPERM, as for mseal'ed memory): unmapping or remapping an
     * island would send later syscalls into whatever replaced it. */
    if (sys_no == __NR_munmap || sys_no == __NR_mprotect || sys_no == __NR_pkey_mprotect ||
        sys_no == __NR_mremap ||
        (sys_no == __NR_mmap && (a[3] & 0x10) && !(a[3] & 0x100000)) ||
        (sys_no == __NR_madvise && ((int)a[2] == 4 || (int)a[2] == 8 || (int)a[2] == 9 ||
                                    (int)a[2] == 10 || (int)a[2] == 18))) {
        if (hook_protected_overlap((uintptr_t)a[0], (size_t)a[1]) ||
            (sys_no == __NR_mremap && (a[3] & 2 /* MREMAP_FIXED */) &&
             hook_protected_overlap((uintptr_t)a[4], (size_t)a[2])))
            return -EPERM;
    }
#ifdef PROOT_PATH
    if (sys_no == __NR_rt_sigaction && (int)a[0] == 31 /* SIGSYS */ &&
        g_payload_config.seccomp_backstop)
        return backstop_sigaction(a);
    /* The HarmonyOS kernel exempts syscalls from writable+executable pages
     * from seccomp, and code written there after mapping is never hooked:
     * under the backstop such mappings are refused (W^X). */
    if (g_payload_config.seccomp_backstop && (sys_no == __NR_mmap || sys_no == __NR_mprotect ||
        sys_no == __NR_pkey_mprotect) && (a[2] & 6) == 6)
        return -EACCES;
#endif
    int named = sys_no == __NR_accept || sys_no == __NR_accept4 ||
        sys_no == __NR_getsockname || sys_no == __NR_getpeername;
    unsigned capacity = named && a[1] && a[2] ? *(unsigned *)a[2] : 0;
#ifdef FD_EXPERIMENT
    long ret = fd_experiment_dispatch(sys_no, args);
#else
    long ret = syscall_handle_common(sys_no, args);
#endif
    if (!ret) fake_owner(sys_no, a);
#ifdef PROOT_PATH
    /* struct utsname: six 65-byte fields; sysname first, release third. */
    if (!ret && sys_no == __NR_uname && a[0]) {
        if (g_payload_config.kernel_sysname[0])
            memcpy((char *)a[0], g_payload_config.kernel_sysname, 65);
        if (g_payload_config.kernel_release[0])
            memcpy((char *)a[0] + 130, g_payload_config.kernel_release, 65);
    }
#endif
#ifdef PROOT_PATH
    if (ret >= 0 && capacity)
        proot_socket_name(sys_no, sys_no == __NR_accept || sys_no == __NR_accept4 ? ret : a[0],
                          (void *)a[1], (unsigned *)a[2], capacity);
#endif
    return ret;
}
