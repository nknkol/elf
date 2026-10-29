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
/* Effective non-deny binds, as the bridge derives them from the same table. */
static size_t exposed_binds(const BindingTable *t, const struct fs_policy *p,
                            const char **out)
{
    size_t count = 0, id;
    for (size_t i = 0; i < t->count; i++)
        if (binding_table_mount_id(t, t->entries[i].guest, &id) == 0 && id == i + 1 &&
            p->mounts[id] != FS_DENY)
            out[count++] = t->entries[i].guest;
    return count;
}
static enum fs_visibility visible(const BindingTable *t, const struct fs_policy *p,
                                  const char *canonical)
{
    const char *exposed[16];
    size_t id, count = exposed_binds(t, p, exposed);
    assert(binding_table_mount_id(t, canonical, &id) == 0);
    return fs_policy_visibility(p, id, canonical, exposed, count);
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
    /* Deny root keeps only the lookup chain to exposed binds. */
    assert(visible(&table, &policy, "/") == FS_TRAVERSE);
    assert(visible(&table, &policy, "/etc") == FS_HIDDEN);
    assert(visible(&table, &policy, "/etc/passwd") == FS_HIDDEN);
    assert(visible(&table, &policy, "/wor") == FS_HIDDEN);
    assert(visible(&table, &policy, "/work-other") == FS_HIDDEN);
    assert(visible(&table, &policy, "/work") == FS_VISIBLE);
    assert(visible(&table, &policy, "/work/tools/file") == FS_VISIBLE);
    assert(visible(&table, &policy, "/work/secret") == FS_HIDDEN);
    assert(visible(&table, &policy, "/work/secret/key") == FS_HIDDEN);
    {
        /* deny bind between exposed parents: rw /a, deny /a/s, ro /a/s/t. */
        const PathBinding nested[] = {{"/a", "/h/a"}, {"/a/s", "/h/s"},
                                      {"/a/s/t", "/h/t"}, {"/x/y", "/h/y"}};
        const BindingTable inner = {"/", nested, 4};
        const enum fs_access modes[] = {FS_DENY, FS_READ_WRITE, FS_DENY,
                                        FS_READ_ONLY, FS_DENY};
        const struct fs_policy p = {modes, 5};
        assert(binding_table_validate(&inner) == 0);
        assert(visible(&inner, &p, "/a/s") == FS_TRAVERSE);
        assert(visible(&inner, &p, "/a/s/other") == FS_HIDDEN);
        assert(visible(&inner, &p, "/a/s/t/file") == FS_VISIBLE);
        assert(visible(&inner, &p, "/a/sibling") == FS_VISIBLE);
        /* A deny-only bind exposes no ancestor chain. */
        assert(visible(&inner, &p, "/x") == FS_HIDDEN);
        assert(visible(&inner, &p, "/x/y") == FS_HIDDEN);
    }
    {
        /* Duplicate destinations: only the winning bind can expose ancestors. */
        const PathBinding twice[] = {{"/d/e", "/h/1"}, {"/d/e", "/h/2"}};
        const BindingTable dup = {"/", twice, 2};
        const enum fs_access modes[] = {FS_DENY, FS_READ_WRITE, FS_DENY};
        const struct fs_policy p = {modes, 3};
        assert(visible(&dup, &p, "/d") == FS_HIDDEN);
        assert(visible(&dup, &p, "/d/e") == FS_HIDDEN);
    }
    const char *only[] = {"/a/b"};
    assert(fs_policy_visibility(&policy, 0, "/a", only, 1) == FS_TRAVERSE);
    assert(fs_policy_visibility(&policy, 0, "/a/b", only, 1) == FS_HIDDEN);
    assert(fs_policy_visibility(&policy, 0, "relative", only, 1) == FS_HIDDEN);
    assert(fs_policy_visibility(&policy, 8, "/a", only, 1) == FS_HIDDEN);
    assert(fs_policy_visibility(NULL, 0, "/a", only, 1) == FS_HIDDEN);
    assert(fs_policy_visibility(&bad, 0, "/a", only, 1) == FS_HIDDEN);
    puts("PASS: mount policy, nested overrides, unknown origins, two-path mutations and visibility");
}
