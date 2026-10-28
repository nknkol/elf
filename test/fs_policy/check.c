/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "fs_policy.h"
#include "path/binding_core.h"

static int path_check(const BindingTable *t, const struct fs_policy *p,
                      const char *canonical, enum fs_operation operation)
{
    size_t id;
    assert(binding_table_mount_id(t, canonical, &id) == 0);
    return fs_policy_check(p, id, true, operation);
}
int main(void)
{
    const PathBinding bindings[] = {
        {"/work", "/host/work"}, {"/work/tools", "/host/tools"},
        {"/work/tools/cache", "/host/cache"}, {"/alias", "/host/work"},
        {"/duplicate", "/old"}, {"/duplicate", "/new"},
        {"/work/secret", "/secret"}
    };
    const BindingTable table = {"/", bindings, 7};
    const enum fs_access access[] = {FS_DENY, FS_READ_WRITE, FS_READ_ONLY,
        FS_READ_WRITE, FS_READ_WRITE, FS_READ_WRITE, FS_READ_ONLY, FS_DENY};
    const struct fs_policy policy = {access, 8};
    assert(binding_table_validate(&table) == 0);
    assert(fs_policy_validate(&policy, table.count) == 0);
    assert(path_check(&table, &policy, "/etc/passwd", FS_OBSERVE) == -EACCES);
    assert(path_check(&table, &policy, "/work/file", FS_MUTATE) == 0);
    assert(path_check(&table, &policy, "/work-other/file", FS_OBSERVE) == -EACCES);
    assert(path_check(&table, &policy, "/work/tools/file", FS_OBSERVE) == 0);
    assert(path_check(&table, &policy, "/work/tools/file", FS_MUTATE) == -EROFS);
    assert(path_check(&table, &policy, "/work/tools/cache/file", FS_MUTATE) == 0);
    assert(path_check(&table, &policy, "/duplicate/file", FS_MUTATE) == -EROFS);
    assert(path_check(&table, &policy, "/work/secret/key", FS_OBSERVE) == -EACCES);
    /* Same host backing does not merge distinct virtual mounts. */
    assert(fs_policy_check_pair(&policy, 1, true, 4, true) == -EXDEV);
    assert(fs_policy_check_pair(&policy, 1, true, 1, true) == 0);
    assert(fs_policy_check_pair(&policy, 2, true, 1, true) == -EROFS);
    assert(fs_policy_check_pair(&policy, 1, true, 2, true) == -EROFS);
    assert(fs_policy_check_pair(&policy, 1, true, 1, false) == -EACCES);
    assert(fs_policy_check_pair(&policy, 1, false, 1, true) == -EACCES);
    /* FD mount observations use the same decision; unknown is never writable. */
    assert(fs_policy_check(&policy, 1, false, FS_OBSERVE) == -EACCES);
    assert(fs_policy_check(&policy, 2, true, FS_MUTATE) == -EROFS);
    assert(fs_policy_check(&policy, 8, true, FS_OBSERVE) == -EACCES);
    assert(fs_policy_check(NULL, 1, true, FS_MUTATE) == -EACCES);
    assert(fs_policy_check(&policy, 1, true, (enum fs_operation)99) == -EINVAL);
    assert(fs_policy_validate(&policy, 6) == -EINVAL);
    assert(fs_policy_validate(&policy, (size_t)-1) == -EINVAL);
    assert(fs_policy_validate(NULL, 0) == -EINVAL);
    const enum fs_access invalid[] = {(enum fs_access)99};
    const struct fs_policy bad = {invalid, 1}, empty = {NULL, 0};
    assert(fs_policy_validate(&bad, 0) == -EINVAL);
    assert(fs_policy_validate(&empty, 0) == -EINVAL);
    assert(fs_policy_check(&bad, 0, true, FS_MUTATE) == -EACCES);
    puts("PASS: mount policy, nested overrides, unknown origins and two-path mutations");
}
