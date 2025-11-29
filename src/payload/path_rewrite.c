#include "config.h"
#include "mini_libc.h"
#include "path_rewrite.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))

static size_t s_len(const char *s)
{
    return sys_strlen(s);
}

static int s_ncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = a[i];
        unsigned char cb = b[i];
        if (ca != cb)
            return (ca < cb) ? -1 : 1;
        if (ca == '\0')
            return 0;
    }
    return 0;
}

static void s_copy(char *dst, size_t dst_sz, const char *src, size_t n)
{
    if (!dst || dst_sz == 0)
        return;
    size_t i = 0;
    while (i + 1 < dst_sz && i < n && src && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static int has_prefix(const char *path, const char *prefix)
{
    size_t plen = s_len(prefix);
    if (plen == 0)
        return 0;
    if (s_ncmp(path, prefix, plen) != 0)
        return 0;
    char tail = path[plen];
    return tail == '\0' || tail == '/' ? 1 : 0;
}

static size_t join_paths(char *out, size_t out_sz,
                         const char *left, size_t left_len,
                         const char *right)
{
    size_t pos = 0;
    if (out_sz == 0)
        return 0;

    /* copy left */
    for (; pos + 1 < out_sz && left && pos < left_len; pos++)
        out[pos] = left[pos];

    int left_has_slash = (pos > 0 && out[pos - 1] == '/');
    int right_has_slash = (right && right[0] == '/');

    if (!left_has_slash && !right_has_slash) {
        if (pos + 1 < out_sz)
            out[pos++] = '/';
    } else if (left_has_slash && right_has_slash) {
        /* avoid double slash by skipping right's leading slash */
        right++;
    }

    size_t i = 0;
    while (right && right[i] && pos + 1 < out_sz) {
        out[pos++] = right[i++];
    }
    out[pos] = '\0';
    return pos;
}

static int apply_bind(char *out, size_t out_sz, const char *in_path)
{
    payload_config_t *cfg = &g_payload_config;
    for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
        const char *src = cfg->binds[i].src;
        const char *dst = cfg->binds[i].dst;
        size_t src_len = s_len(src);
        if (src_len == 0)
            continue;
        if (!has_prefix(in_path, src))
            continue;
        const char *suffix = in_path + src_len;
        size_t dst_len = s_len(dst);
        if (dst_len + s_len(suffix) + 1 >= out_sz) {
            /* truncate safely */
            s_copy(out, out_sz, dst, dst_len);
            size_t cur = s_len(out);
            join_paths(out, out_sz, out, cur, suffix);
        } else {
            /* write fresh into out */
            join_paths(out, out_sz, dst, dst_len, suffix);
        }
        return 1;
    }
    return 0;
}

static void apply_root(char *out, size_t out_sz)
{
    payload_config_t *cfg = &g_payload_config;
    if (cfg->root[0] == '\0')
        return;
    if (out[0] != '/')
        return; /* relative path: leave untouched */
    if (has_prefix(out, cfg->root))
        return; /* already rooted */

    char original[CONFIG_MAX_PATH];
    s_copy(original, sizeof(original), out, s_len(out));

    size_t root_len = s_len(cfg->root);
    if (root_len + s_len(original) + 1 >= out_sz) {
        /* still attempt to join with truncation */
    }
    join_paths(out, out_sz, cfg->root, root_len, original);
}

const char *rewrite_path(const char *in, char *out, size_t out_sz)
{
    if (!in || !out || out_sz == 0)
        return in;

    s_copy(out, out_sz, in, s_len(in));

    /* Bind overlay first */
    if (!apply_bind(out, out_sz, out)) {
        /* If no bind matched, apply root prefix */
        apply_root(out, out_sz);
    }

    return out;
}

static int apply_bind_reverse(char *out, size_t out_sz, const char *in_path)
{
    payload_config_t *cfg = &g_payload_config;
    for (int i = 0; i < cfg->bind_count && i < CONFIG_MAX_BINDS; i++) {
        const char *src = cfg->binds[i].src; /* guest */
        const char *dst = cfg->binds[i].dst; /* host */
        size_t dst_len = s_len(dst);
        if (dst_len == 0)
            continue;
        if (!has_prefix(in_path, dst))
            continue;
        const char *suffix = in_path + dst_len;
        join_paths(out, out_sz, src, s_len(src), suffix);
        return 1;
    }
    return 0;
}

static int apply_root_reverse(char *out, size_t out_sz, const char *in_path)
{
    payload_config_t *cfg = &g_payload_config;
    size_t root_len = s_len(cfg->root);
    if (root_len == 0)
        return 0;
    if (!has_prefix(in_path, cfg->root))
        return 0;

    const char *suffix = in_path + root_len;
    if (*suffix == '\0')
        suffix = "/";
    s_copy(out, out_sz, suffix, s_len(suffix));
    return 1;
}

const char *rewrite_path_from_host(const char *in, char *out, size_t out_sz)
{
    if (!in || !out || out_sz == 0)
        return in;

    s_copy(out, out_sz, in, s_len(in));

    if (apply_bind_reverse(out, out_sz, out))
        return out;

    apply_root_reverse(out, out_sz, out);
    return out;
}
