#include <asm/unistd.h>
#include <errno.h>
#include "syscall_nums.h"
#include "syscall_hooks.h"
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
    if (ret >= 0 && capacity)
        proot_socket_name(sys_no, sys_no == __NR_accept || sys_no == __NR_accept4 ? ret : a[0],
                          (void *)a[1], (unsigned *)a[2], capacity);
#endif
    return ret;
}
