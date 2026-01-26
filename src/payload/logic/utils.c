#include "utils.h"
#include "syscall_nums.h"
#include "mini_libc.h"

// Constants used by functions moved from syscall_hooks.c
#define AT_FDCWD    (-100)
#define UTSNAME_LEN 65

// Struct needed by is_harmonyos()
struct utsname {
    char sysname[UTSNAME_LEN];
    char nodename[UTSNAME_LEN];
    char release[UTSNAME_LEN];
    char version[UTSNAME_LEN];
    char machine[UTSNAME_LEN];
    char domainname[UTSNAME_LEN];
};

// Extern declarations for functions defined elsewhere
extern long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

int sys_streq(const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    while (*a && *b) {
        if (*a != *b)
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

int is_harmonyos(void)
{
    static int cached = -1;
    if (cached >= 0)
        return cached;

    struct utsname u;
    long rc = raw_syscall(SYS_uname, (long)&u, 0, 0, 0, 0, 0);
    if (rc < 0) {
        cached = 0;
        return cached;
    }

    cached = sys_streq(u.sysname, "HarmonyOS") ? 1 : 0;
    return cached;
}

void small_copy(char *dst, const char *src)
{
    if (!dst || !src) return;
    while (*src) {
        *dst++ = *src++;
    }
    *dst = 0;
}

void format_range(int min, int max, char *buf, size_t buf_sz)
{
    if (!buf || buf_sz == 0)
        return;
    size_t pos = 0;
    int vals[2] = { min, max };
    for (int idx = 0; idx < 2; idx++) {
        int v = vals[idx];
        char tmp[32];
        int tpos = 0;
        if (v == 0) {
            tmp[tpos++] = '0';
        } else {
            int sign = 0;
            if (v < 0) { sign = 1; v = -v; }
            char rev[32];
            int rpos = 0;
            while (v > 0 && rpos < (int)sizeof(rev)) {
                rev[rpos++] = '0' + (v % 10);
                v /= 10;
            }
            if (sign && rpos < (int)sizeof(rev))
                rev[rpos++] = '-';
            while (rpos > 0 && tpos + 1 < (int)sizeof(tmp))
                tmp[tpos++] = rev[--rpos];
        }
        for (int i = 0; i < tpos && pos + 1 < buf_sz; i++)
            buf[pos++] = tmp[i];
        if (idx == 0 && pos + 1 < buf_sz)
            buf[pos++] = '-';
    }
    buf[pos < buf_sz ? pos : buf_sz - 1] = '\0';
}

void format_int(long v, char *buf, size_t buf_sz)
{
    if (!buf || buf_sz == 0)
        return;
    size_t pos = 0;
    int sign = 0;
    if (v < 0) {
        sign = 1;
        v = -v;
    }
    char rev[32];
    size_t rpos = 0;
    if (v == 0) {
        rev[rpos++] = '0';
    } else {
        while (v > 0 && rpos < sizeof(rev)) {
            rev[rpos++] = '0' + (v % 10);
            v /= 10;
        }
    }
    if (sign && rpos < sizeof(rev))
        rev[rpos++] = '-';
    while (rpos > 0 && pos + 1 < buf_sz)
        buf[pos++] = rev[--rpos];
    buf[pos < buf_sz ? pos : buf_sz - 1] = '\0';
}

int path_exists(const char *path)
{
    if (!path || !path[0])
        return 0;
    long r = raw_syscall(SYS_faccessat, AT_FDCWD, (long)path, 0, 0, 0, 0);
    return r == 0;
}

size_t dir_len(const char *path)
{
    size_t len = sys_strlen(path);
    while (len > 0 && path[len - 1] != '/')
        len--;
    return len ? len - (len == 1 ? 1 : 0) : 0;
}

void join_paths(char *out, size_t out_sz,
                       const char *base, size_t base_len,
                       const char *suffix)
{
    size_t pos = 0;
    if (!out || out_sz == 0)
        return;

    for (; pos + 1 < out_sz && base && pos < base_len; pos++)
        out[pos] = base[pos];

    if (pos > 0 && out[pos - 1] != '/' && suffix && suffix[0] != '/') {
        if (pos + 1 < out_sz)
            out[pos++] = '/';
    } else if (pos > 0 && out[pos - 1] == '/' && suffix && suffix[0] == '/') {
        suffix++;
    }

    size_t i = 0;
    while (suffix && suffix[i] && pos + 1 < out_sz) {
        out[pos++] = suffix[i++];
    }
    out[pos] = '\0';
}

const char *path_basename(const char *path)
{
    if (!path)
        return NULL;
    const char *last = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' && p[1] != '\0')
            last = p + 1;
    }
    return last;
}

int format_fd_path(char *out, size_t out_sz, int fd)
{
    if (!out || out_sz == 0 || fd < 0)
        return 0;
    const char *prefix = "/proc/self/fd/";
    size_t pos = 0;
    while (prefix[pos] && pos + 1 < out_sz) {
        out[pos] = prefix[pos];
        pos++;
    }
    if (pos + 2 >= out_sz)
        return 0;
    char numbuf[16];
    int npos = 0;
    if (fd == 0) {
        numbuf[npos++] = '0';
    } else {
        int tmp = fd;
        char rev[16];
        int rpos = 0;
        while (tmp > 0 && rpos < (int)sizeof(rev)) {
            rev[rpos++] = '0' + (tmp % 10);
            tmp /= 10;
        }
        while (rpos > 0)
            numbuf[npos++] = rev[--rpos];
    }
    if (pos + npos + 1 >= out_sz)
        return 0;
    for (int i = 0; i < npos; i++)
        out[pos++] = numbuf[i];
    out[pos] = '\0';
    return 1;
}

void zero_region(void *addr, unsigned long len)
{
    unsigned char *p = (unsigned char *)addr;
    for (unsigned long i = 0; i < len; i++)
        p[i] = 0;
}
