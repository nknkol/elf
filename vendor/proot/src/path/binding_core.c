/* SPDX-License-Identifier: GPL-2.0-or-later
 * Matching/root precedence derived from PRoot path/binding.c (GPL-2.0+).
 */
#include <errno.h>
#include <string.h>
#include "path/binding_core.h"

static bool prefix_of(const char *prefix, const char *path)
{
    Comparison c = compare_paths(prefix, path);
    return c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX;
}
bool binding_matches_core(const char *root, Side side, const char *prefix, const char *path)
{
    if (!prefix_of(prefix, path)) return false;
    /* Preserve PRoot's rootfs precedence over reverse asymmetric binds. */
    if (side == HOST && root && strcmp(root, "/") && prefix_of(root, path))
        return false;
    return side == HOST || side == GUEST;
}
int binding_replace_core(char path[PATH_MAX], const char *from, const char *to)
{
    size_t len = strnlen(path, PATH_MAX);
    size_t old = strnlen(from, PATH_MAX), newlen = strnlen(to, PATH_MAX);
    if (len == PATH_MAX || old == PATH_MAX || newlen == PATH_MAX)
        return -ENAMETOOLONG;
    if (!old || !newlen || from[0] != '/' || to[0] != '/' ||
        !prefix_of(from, path)) return -EINVAL;
    if (strcmp(from, to) == 0) return 0;
    /* Root prefixes include the separator; other prefixes do not. */
    const char *tail = path + (old == 1 ? 0 : old);
    if (newlen == 1 && *tail == '/') tail++;
    if (old == 1 && len == 1) tail = path + 1;
    size_t rest = strlen(tail);
    if (newlen + rest >= PATH_MAX) return -ENAMETOOLONG;
    memmove(path + newlen, tail, rest + 1);
    memcpy(path, to, newlen);
    return 1;
}
static int validate_prefix(const char *s)
{
    if (!s || s[0] != '/') return -EINVAL;
    size_t n = strnlen(s, PATH_MAX);
    if (n == PATH_MAX) return -ENAMETOOLONG;
    if (n == 1) return 0;
    if (s[n-1] == '/') return -EINVAL;
    for (const char *p=s+1; *p;) {
        const char *end=strchr(p, '/');
        size_t len=end ? (size_t)(end-p) : strlen(p);
        if (!len || (len==1 && p[0]=='.') ||
            (len==2 && p[0]=='.' && p[1]=='.')) return -EINVAL;
        if (!end) break;
        p=end+1;
    }
    return 0;
}
int binding_table_validate(const BindingTable *t)
{
    if (!t || (t->count && !t->entries)) return -EINVAL;
    int rc=validate_prefix(t->root);
    if (rc<0) return rc;
    for (size_t i=0;i<t->count;i++) {
        rc=validate_prefix(t->entries[i].guest); if(rc<0) return rc;
        rc=validate_prefix(t->entries[i].host); if(rc<0) return rc;
        /* Root is a separate explicit field, not a competing bind. */
        if (!strcmp(t->entries[i].guest,"/")) return -EINVAL;
    }
    return 0;
}
static bool shadowed(const BindingTable *t, size_t i)
{
    for (size_t j=i+1;j<t->count;j++)
        if (!strcmp(t->entries[i].guest,t->entries[j].guest)) return true;
    return false;
}
int binding_table_mount_id(const BindingTable *t, const char *guest, size_t *id)
{
    if (!t || !guest || !id || guest[0] != '/')
        return -EINVAL;
    if (strnlen(guest, PATH_MAX) == PATH_MAX)
        return -ENAMETOOLONG;
    size_t best = 0;
    *id = 0;
    for (size_t i = 0; i < t->count; i++) {
        if (shadowed(t, i))
            continue;
        const char *prefix = t->entries[i].guest;
        size_t len = strlen(prefix);
        if (binding_matches_core(t->root, GUEST, prefix, guest) && len >= best) {
            *id = i + 1;
            best = len;
        }
    }
    return 0;
}

int binding_table_map(const BindingTable *t, Side side, const char *path, char out[PATH_MAX])
{
    if (!t || !path || !out || (side!=HOST && side!=GUEST) || path[0]!='/')
        return -EINVAL;
    if (strnlen(path,PATH_MAX)==PATH_MAX) return -ENAMETOOLONG;
    const char *from=NULL, *to=NULL;
    size_t best=0;
    for (size_t i=0;i<t->count;i++) {
        const PathBinding *b=&t->entries[i];
        if (shadowed(t,i)) continue;
        const char *ref=side==GUEST ? b->guest : b->host;
        if (binding_matches_core(t->root,side,ref,path) && strlen(ref)>=best) {
            from=ref; to=side==GUEST ? b->host : b->guest; best=strlen(ref);
        }
    }
    if (!from) {
        from=side==GUEST ? "/" : t->root;
        to=side==GUEST ? t->root : "/";
        if (!prefix_of(from,path)) return -EXDEV;
    }
    /* out may alias path. Prefix strings must not alias either buffer. */
    memmove(out,path,strlen(path)+1);
    int rc=binding_replace_core(out,from,to);
    return rc<0 ? rc : 0;
}
