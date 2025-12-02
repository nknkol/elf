#include "execve_utils.h"
#include "mini_libc.h"
#include "path_rewrite.h"

static int has_prefix(const char *s, const char *key, size_t key_len)
{
    if (!s || !key)
        return 0;
    for (size_t i = 0; i < key_len; i++) {
        if (s[i] != key[i])
            return 0;
    }
    return 1;
}

static void rebuild_kv(const char *key, const char *val, char *out, size_t out_sz)
{
    size_t pos = 0;
    if (!out || out_sz == 0)
        return;
    if (key) {
        for (size_t i = 0; key[i] && pos + 1 < out_sz; i++)
            out[pos++] = key[i];
    }
    if (val) {
        for (size_t i = 0; val[i] && pos + 1 < out_sz; i++)
            out[pos++] = val[i];
    }
    out[pos] = '\0';
}

size_t safe_cpy(char *dst, size_t dst_sz, const char *src)
{
    if (!dst || dst_sz == 0)
        return 0;
    size_t i = 0;
    while (i + 1 < dst_sz && src && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return i;
}

void rewrite_path_list(const char *val, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) {
        return;
    }
    size_t pos = 0;
    size_t i = 0;
    while (val && val[i] && pos + 1 < out_sz) {
        size_t start = i;
        while (val[i] && val[i] != ':')
            i++;
        size_t len = i - start;
        char segment[CONFIG_MAX_PATH];
        size_t seg_len = 0;
        if (len + 1 < sizeof(segment)) {
            for (size_t k = 0; k < len; k++)
                segment[k] = val[start + k];
            segment[len] = '\0';
            if (segment[0] == '/') {
                rewrite_path(segment, segment, sizeof(segment));
            }
            while (segment[seg_len] && pos + 1 < out_sz) {
                out[pos++] = segment[seg_len++];
            }
        }
        if (val[i] == ':' && pos + 1 < out_sz) {
            out[pos++] = ':';
            i++;
            continue;
        }
        if (val[i] == '\0')
            break;
    }
    out[pos] = '\0';
}

void rewrite_env_entry(const char *in, char *out, size_t out_sz)
{
    if (!out || out_sz == 0) {
        return;
    }
    /* Default copy-through */
    safe_cpy(out, out_sz, in);
    if (!in)
        return;

    static const char *const list_keys[] = {
        "PATH=",
        "LD_LIBRARY_PATH=",
        "LD_PRELOAD=",
        NULL
    };
    static const char *const abs_keys[] = {
        "PWD=",
        "HOME=",
        "TMPDIR=",
        "TMP=",
        "TEMP=",
        NULL
    };

    for (int k = 0; list_keys[k]; k++) {
        const char *key = list_keys[k];
        size_t key_len = sys_strlen(key);
        if (!has_prefix(in, key, key_len))
            continue;

        char value[CONFIG_MAX_PATH];
        safe_cpy(value, sizeof(value), in + key_len);
        char rewritten[CONFIG_MAX_PATH];
        rewrite_path_list(value, rewritten, sizeof(rewritten));
        rebuild_kv(key, rewritten, out, out_sz);
        return;
    }

    for (int k = 0; abs_keys[k]; k++) {
        const char *key = abs_keys[k];
        size_t key_len = sys_strlen(key);
        if (!has_prefix(in, key, key_len))
            continue;
        const char *value = in + key_len;
        if (!value || value[0] != '/')
            return; /* relative or empty: keep original */

        char rewritten[CONFIG_MAX_PATH];
        rewrite_path(value, rewritten, sizeof(rewritten));
        rebuild_kv(key, rewritten, out, out_sz);
        return;
    }
}

int build_exec_env(const char *const *in, char **out,
                   char buf[][CONFIG_MAX_PATH], size_t max_items)
{
    if (!out)
        return 0;
    size_t idx = 0;
    for (; idx + 1 < max_items; idx++) {
        const char *s = in ? in[idx] : NULL;
        if (!s)
            break;
        rewrite_env_entry(s, buf[idx], sizeof(buf[idx]));
        out[idx] = buf[idx];
    }
    out[idx] = NULL;
    if (in && idx + 1 == max_items && in[idx])
        return 0;
    return 1;
}
