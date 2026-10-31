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
#include "host_syscall.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#define KEEP 0xffffffffu
enum { REAL, EFFECTIVE, SAVED, FS };
static uint32_t ids[2][4]; /* uid then gid sets. */
static uint32_t groups[32];
static int group_count;
static int loaded;

static uint32_t *set_of(int group)
{
    if (!__atomic_load_n(&loaded, __ATOMIC_ACQUIRE)) {
        for (int i = 0; i < 8; i++)
            ids[i / 4][i % 4] = g_payload_config.fake_ids[i];
        group_count = g_payload_config.fake_group_count;
        if (group_count < 0 || group_count > 32) { group_count = 1; groups[0] = 0; }
        for (int i = 0; i < group_count; i++) groups[i] = g_payload_config.fake_groups[i];
        __atomic_store_n(&loaded, 1, __ATOMIC_RELEASE);
    }
    return ids[group];
}

static int privileged(void) { return set_of(0)[EFFECTIVE] == 0; }

static int member(const uint32_t *set, uint32_t id)
{
    return id == set[REAL] || id == set[EFFECTIVE] || id == set[SAVED];
}

static long set_one(int group, uint32_t id)
{
    uint32_t *set = set_of(group);
    if (privileged()) {
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
    if (!privileged() &&
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
    if (!privileged() &&
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
    if (privileged() || member(set, id) || id == set[FS]) set[FS] = id;
    return old;
}

int fake_ids_syscall(long number, long a[6], long *result)
{
    uint32_t x = (uint32_t)a[0], y = (uint32_t)a[1], z = (uint32_t)a[2];
    switch (number) {
    case __NR_getuid: *result = set_of(0)[REAL]; break;
    case __NR_geteuid: *result = set_of(0)[EFFECTIVE]; break;
    case __NR_getgid: *result = set_of(1)[REAL]; break;
    case __NR_getegid: *result = set_of(1)[EFFECTIVE]; break;
    case __NR_getresuid: *result = get_res(0, a); break;
    case __NR_getresgid: *result = get_res(1, a); break;
    case __NR_setuid: *result = set_one(0, x); break;
    case __NR_setgid: *result = set_one(1, x); break;
    case __NR_setreuid: *result = set_re(0, x, y); break;
    case __NR_setregid: *result = set_re(1, x, y); break;
    case __NR_setresuid: *result = set_res(0, x, y, z); break;
    case __NR_setresgid: *result = set_res(1, x, y, z); break;
    case __NR_setfsuid: *result = set_fs(0, x); break;
    case __NR_setfsgid: *result = set_fs(1, x); break;
    case __NR_setgroups: {
        size_t size = (size_t)(int)a[0];
        set_of(0);
        if (!privileged()) { *result = -EPERM; break; }
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

int fake_ids_privileged(void) { return privileged(); }

uint32_t fake_ids_owner(int group) { return set_of(group)[SAVED]; }

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
uint32_t fake_ids_reported_owner(uint32_t id, int group)
{
    collect_owners();
    if (__atomic_load_n(&owner_state, __ATOMIC_ACQUIRE) != 2) return id;
    for (int i = 0; i < owner_count; i++)
        if (id == (group ? owner_gid[i] : owner_uid[i])) return fake_ids_owner(group);
    return id;
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
    if (uid_hit) owner[0] = fake_ids_owner(0);
    if (gid_hit) owner[1] = fake_ids_owner(1);
}

