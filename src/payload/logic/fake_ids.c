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
