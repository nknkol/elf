/* SPDX-License-Identifier: GPL-2.0-or-later */
/* PRoot fake_id0: the guest's credentials, starting as root. The set*id
 * calls follow Linux rules as if the kernel held these ids (privilege is a
 * fake effective uid 0); the real credentials never change. The state is
 * per process: threads share it (libc applies set*id to every thread with
 * the same values), fork copies it and the exec chain passes it on. */
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include "fake_ids.h"
#include "container_state.h"
#include "host_syscall.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#define KEEP 0xffffffffu
enum { REAL, EFFECTIVE, SAVED, FS };
static uint32_t ids[2][4]; /* uid then gid sets. */
static uint32_t groups[32];
static int group_count;
static int loaded;

/* Capabilities, as Linux gives them to these ids (capabilities(7)), out of
 * Docker's default set: a root process has them in its permitted and
 * effective sets, set*id moves them as the kernel would (PR_SET_KEEPCAPS
 * included), capget/capset and the prctl capability options work on them,
 * and they decide the privileged set*id, chown and chmod. An exec starts
 * over from the ids (no file capabilities, no ambient set kept); the
 * bounding set too. /proc/<pid>/status still shows the real (empty) sets. */
enum { CAP_CHOWN_ = 0, CAP_FOWNER_ = 3, CAP_SETGID_ = 6, CAP_SETUID_ = 7, CAP_SETPCAP_ = 8, CAP_LAST_ = 40 };
#define DOCKER_CAPS 0xa80425fbull
/* Those cleared or raised with the fs uid (capabilities(7)). */
#define FS_CAPS 0x000000010800021full
static uint64_t cap_eff, cap_prm, cap_inh, cap_amb, cap_bnd;
static int keepcaps;

static void caps_from_ids(void)
{
    cap_bnd = DOCKER_CAPS;
    cap_prm = ids[0][REAL] == 0 || ids[0][EFFECTIVE] == 0 ? cap_bnd : 0;
    cap_eff = ids[0][EFFECTIVE] == 0 ? cap_prm : 0;
    cap_inh = cap_amb = 0;
    keepcaps = 0;
}

static uint32_t *set_of(int group)
{
    if (!__atomic_load_n(&loaded, __ATOMIC_ACQUIRE)) {
        for (int i = 0; i < 8; i++)
            ids[i / 4][i % 4] = g_payload_config.fake_ids[i];
        group_count = g_payload_config.fake_group_count;
        if (group_count < 0 || group_count > 32) { group_count = 1; groups[0] = 0; }
        for (int i = 0; i < group_count; i++) groups[i] = g_payload_config.fake_groups[i];
        caps_from_ids();
        __atomic_store_n(&loaded, 1, __ATOMIC_RELEASE);
    }
    return ids[group];
}

static int capable(int cap) { set_of(0); return (cap_eff >> cap) & 1; }
/* What changes the set (group 0: uid, 1: gid) needs. */
static int privileged_for(int group) { return capable(group ? CAP_SETGID_ : CAP_SETUID_); }

/* After a change of the uids from old (r, e, s, fs): the capability sets
 * as the kernel moves them. */
static void caps_after_uids(const uint32_t old[4])
{
    const uint32_t *now = ids[0];
    if ((!old[REAL] || !old[EFFECTIVE] || !old[SAVED]) && now[REAL] && now[EFFECTIVE] && now[SAVED]) {
        if (!keepcaps) cap_prm = 0;
        cap_eff = cap_amb = 0;
    }
    if (!old[EFFECTIVE] && now[EFFECTIVE]) cap_eff = 0;
    if (old[EFFECTIVE] && !now[EFFECTIVE]) cap_eff = cap_prm;
    if (!old[FS] && now[FS]) cap_eff &= ~FS_CAPS;
    if (old[FS] && !now[FS]) cap_eff |= cap_prm & FS_CAPS;
}

static int member(const uint32_t *set, uint32_t id)
{
    return id == set[REAL] || id == set[EFFECTIVE] || id == set[SAVED];
}

static long set_one(int group, uint32_t id)
{
    uint32_t *set = set_of(group);
    if (privileged_for(group)) {
        set[REAL] = set[EFFECTIVE] = set[SAVED] = set[FS] = id;
    } else if (id == set[REAL] || id == set[SAVED]) {
        set[EFFECTIVE] = set[FS] = id;
    } else {
        return -EPERM;
    }
    return 0;
}

static long set_re(int group, uint32_t real, uint32_t effective)
{
    uint32_t *set = set_of(group);
    if (!privileged_for(group) &&
        ((real != KEEP && real != set[REAL] && real != set[EFFECTIVE]) ||
         (effective != KEEP && !member(set, effective))))
        return -EPERM;
    uint32_t old_real = set[REAL];
    if (real != KEEP) set[REAL] = real;
    if (effective != KEEP) set[EFFECTIVE] = effective;
    if (real != KEEP || (effective != KEEP && effective != old_real))
        set[SAVED] = set[EFFECTIVE];
    set[FS] = set[EFFECTIVE];
    return 0;
}

static long set_res(int group, uint32_t real, uint32_t effective, uint32_t saved)
{
    uint32_t *set = set_of(group);
    if (!privileged_for(group) &&
        ((real != KEEP && !member(set, real)) ||
         (effective != KEEP && !member(set, effective)) ||
         (saved != KEEP && !member(set, saved))))
        return -EPERM;
    if (real != KEEP) set[REAL] = real;
    if (effective != KEEP) set[EFFECTIVE] = effective;
    if (saved != KEEP) set[SAVED] = saved;
    set[FS] = set[EFFECTIVE];
    return 0;
}

static long get_res(int group, long a[6])
{
    const uint32_t *set = set_of(group);
    for (int i = 0; i < 3; i++)
        if (!a[i]) return -EFAULT;
    for (int i = 0; i < 3; i++)
        *(uint32_t *)a[i] = set[i];
    return 0;
}

static long set_fs(int group, uint32_t id)
{
    uint32_t *set = set_of(group);
    uint32_t old = set[FS];
    /* Never fails: the previous value is returned either way. */
    if (privileged_for(group) || member(set, id) || id == set[FS]) set[FS] = id;
    return old;
}

/* capget/capset: struct __user_cap_header_struct {u32 version; int pid}
 * and one (version 1) or two {effective, permitted, inheritable} words. */
#define CAP_V1 0x19980330u
#define CAP_V2 0x20071026u
#define CAP_V3 0x20080522u
static int cap_words(const uint32_t *header)
{
    return header[0] == CAP_V1 ? 1 : header[0] == CAP_V2 || header[0] == CAP_V3 ? 2 : 0;
}

static int cap_self(int pid)
{
    return pid == 0 || pid == raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0) ||
           pid == raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
}

static long cap_get(long a[6])
{
    uint32_t *header = (uint32_t *)a[0];
    if (!header) return -EFAULT;
    int words = cap_words(header);
    if (!words) {
        header[0] = CAP_V3;
        return a[1] ? -EINVAL : 0;
    }
    if (!a[1]) return 0;
    if (!cap_self((int)header[1])) return raw_syscall(__NR_capget, a[0], a[1], 0, 0, 0, 0);
    set_of(0);
    uint32_t *data = (uint32_t *)a[1];
    for (int i = 0; i < words; i++) {
        data[i * 3 + 0] = (uint32_t)(cap_eff >> (32 * i));
        data[i * 3 + 1] = (uint32_t)(cap_prm >> (32 * i));
        data[i * 3 + 2] = (uint32_t)(cap_inh >> (32 * i));
    }
    return 0;
}

static long cap_set(long a[6])
{
    uint32_t *header = (uint32_t *)a[0];
    if (!header) return -EFAULT;
    int words = cap_words(header);
    if (!words) { header[0] = CAP_V3; return -EINVAL; }
    if (!cap_self((int)header[1])) return -EPERM;
    if (!a[1]) return -EFAULT;
    set_of(0);
    const uint32_t *data = (const uint32_t *)a[1];
    uint64_t eff = 0, prm = 0, inh = 0;
    for (int i = 0; i < words; i++) {
        eff |= (uint64_t)data[i * 3 + 0] << (32 * i);
        prm |= (uint64_t)data[i * 3 + 1] << (32 * i);
        inh |= (uint64_t)data[i * 3 + 2] << (32 * i);
    }
    if (words == 1) { /* Version 1 leaves the upper words as they are. */
        eff |= cap_eff & ~0xffffffffull;
        prm |= cap_prm & ~0xffffffffull;
        inh |= cap_inh & ~0xffffffffull;
    }
    uint64_t inh_room = cap_inh | (capable(CAP_SETPCAP_) ? cap_bnd : cap_prm);
    if ((prm & ~cap_prm) || (eff & ~prm) || (inh & ~inh_room) || (inh & ~(cap_inh | cap_bnd)))
        return -EPERM;
    cap_eff = eff;
    cap_prm = prm;
    cap_inh = inh;
    cap_amb &= prm & inh;
    return 0;
}

/* prctl capability options; 0 when the option is not one of them. */
static int cap_prctl(long a[6], long *result)
{
    unsigned long option = (unsigned long)a[0], arg = (unsigned long)a[1];
    set_of(0);
    switch (option) {
    case 7: /* PR_GET_KEEPCAPS */
        *result = keepcaps;
        return 1;
    case 8: /* PR_SET_KEEPCAPS */
        if (arg > 1) { *result = -EINVAL; return 1; }
        keepcaps = (int)arg;
        *result = 0;
        return 1;
    case 23: /* PR_CAPBSET_READ */
        *result = arg > CAP_LAST_ ? -EINVAL : (long)((cap_bnd >> arg) & 1);
        return 1;
    case 24: /* PR_CAPBSET_DROP */
        if (arg > CAP_LAST_) { *result = -EINVAL; return 1; }
        if (!capable(CAP_SETPCAP_)) { *result = -EPERM; return 1; }
        cap_bnd &= ~(1ull << arg);
        *result = 0;
        return 1;
    case 47: { /* PR_CAP_AMBIENT */
        unsigned long cap = (unsigned long)a[2];
        if (arg == 4) { cap_amb = 0; *result = 0; return 1; } /* CLEAR_ALL */
        if (arg < 1 || arg > 3 || cap > CAP_LAST_) { *result = -EINVAL; return 1; }
        uint64_t bit = 1ull << cap;
        if (arg == 1) *result = (cap_amb & bit) != 0;            /* IS_SET */
        else if (arg == 3) { cap_amb &= ~bit; *result = 0; }     /* LOWER */
        else if (!(cap_prm & bit) || !(cap_inh & bit)) *result = -EPERM;
        else { cap_amb |= bit; *result = 0; }                    /* RAISE */
        return 1;
    }
    }
    return 0;
}

int fake_ids_syscall(long number, long a[6], long *result)
{
    uint32_t x = (uint32_t)a[0], y = (uint32_t)a[1], z = (uint32_t)a[2];
    switch (number) {
    case __NR_capget: *result = cap_get(a); return 1;
    case __NR_capset: *result = cap_set(a); return 1;
    case __NR_prctl: return cap_prctl(a, result);
    case __NR_setuid: case __NR_setreuid: case __NR_setresuid: case __NR_setfsuid: {
        uint32_t old[4];
        uint32_t *set = set_of(0);
        for (int i = 0; i < 4; i++) old[i] = set[i];
        *result = number == __NR_setuid ? set_one(0, x) : number == __NR_setreuid ? set_re(0, x, y) :
                  number == __NR_setresuid ? set_res(0, x, y, z) : set_fs(0, x);
        caps_after_uids(old);
        return 1;
    }
    }
    switch (number) {
    case __NR_getuid: *result = set_of(0)[REAL]; break;
    case __NR_geteuid: *result = set_of(0)[EFFECTIVE]; break;
    case __NR_getgid: *result = set_of(1)[REAL]; break;
    case __NR_getegid: *result = set_of(1)[EFFECTIVE]; break;
    case __NR_getresuid: *result = get_res(0, a); break;
    case __NR_getresgid: *result = get_res(1, a); break;
    case __NR_setgid: *result = set_one(1, x); break;
    case __NR_setregid: *result = set_re(1, x, y); break;
    case __NR_setresgid: *result = set_res(1, x, y, z); break;
    case __NR_setfsgid: *result = set_fs(1, x); break;
    case __NR_setgroups: {
        size_t size = (size_t)(int)a[0];
        if (!privileged_for(1)) { *result = -EPERM; break; }
        if ((long)(int)a[0] < 0 || size > 32) { *result = -EINVAL; break; }
        if (size && !a[1]) { *result = -EFAULT; break; }
        for (size_t i = 0; i < size; i++) groups[i] = ((const uint32_t *)a[1])[i];
        group_count = (int)size;
        *result = 0;
        break;
    }
    case __NR_getgroups: {
        int size = (int)a[0];
        set_of(0);
        if (size < 0) { *result = -EINVAL; break; }
        if (size && size < group_count) { *result = -EINVAL; break; }
        if (size && group_count && !a[1]) { *result = -EFAULT; break; }
        for (int i = 0; size && i < group_count; i++) ((uint32_t *)a[1])[i] = groups[i];
        *result = group_count;
        break;
    }
    default: return 0;
    }
    return 1;
}

int fake_ids_capable(int cap) { return capable(cap); }

uint32_t fake_ids_owner(int group) { return set_of(group)[SAVED]; }
uint32_t fake_ids_effective(int group) { return set_of(group)[EFFECTIVE]; }
uint32_t fake_ids_fs(int group) { return set_of(group)[FS]; }

int fake_ids_groups(uint32_t out[32])
{
    set_of(0);
    for (int i = 0; i < group_count; i++) out[i] = groups[i];
    return group_count;
}

int fake_ids_current(uint32_t out[8])
{
    int changed = 0;
    for (int i = 0; i < 8; i++) {
        out[i] = set_of(i / 4)[i % 4];
        changed |= out[i] != 0;
    }
    return changed;
}

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
    /* Isolation mode: from the initial loader (a lookup is a round trip). */
    if (g_payload_config.owner_count > 0) {
        for (; n < g_payload_config.owner_count && n < OWNERS && n < CONFIG_OWNERS; n++) {
            owner_uid[n] = g_payload_config.owners[n][0];
            owner_gid[n] = g_payload_config.owners[n][1];
        }
        owner_count = n;
        __atomic_store_n(&owner_state, 2, __ATOMIC_RELEASE);
        return;
    }
    owner_uid[n] = (unsigned)raw_syscall(__NR_getuid, 0, 0, 0, 0, 0, 0);
    owner_gid[n++] = (unsigned)raw_syscall(__NR_getgid, 0, 0, 0, 0, 0, 0);
    for (int i = -1; i < g_payload_config.bind_count && i < CONFIG_MAX_BINDS; i++) {
        const char *host = i < 0 ? g_payload_config.root : g_payload_config.binds[i].dst;
        struct { unsigned char data[128]; } st;
        if (!host[0] || host_syscall(__NR_newfstatat, -100, (long)host, (long)&st, 0, 0, 0) < 0)
            continue;
        if ((*(unsigned *)(st.data + 16) & 0170000) != 0040000) continue;
        owner_uid[n] = *(unsigned *)(st.data + 24);
        owner_gid[n++] = *(unsigned *)(st.data + 28);
    }
    owner_count = n;
    __atomic_store_n(&owner_state, 2, __ATOMIC_RELEASE);
}
int fake_ids_host_owned(uint32_t id, int group)
{
    collect_owners();
    if (__atomic_load_n(&owner_state, __ATOMIC_ACQUIRE) != 2) return 0;
    for (int i = 0; i < owner_count; i++)
        if (id == (group ? owner_gid[i] : owner_uid[i])) return 1;
    return 0;
}
/* With an owner database (R5) the user's own files without a record are
 * the image's: root's. */
static uint32_t own_files_owner(int group) { return owners_enabled() ? 0 : fake_ids_owner(group); }
uint32_t fake_ids_reported_owner(uint32_t id, int group)
{
    return fake_ids_host_owned(id, group) ? own_files_owner(group) : id;
}
void fake_ids_stat_owner(long sys_no, const long *a)
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
    /* The caller's own files belong to its fake saved ids, as in PRoot. */
    if (uid_hit) owner[0] = own_files_owner(0);
    if (gid_hit) owner[1] = own_files_owner(1);
}

