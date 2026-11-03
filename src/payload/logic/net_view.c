/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Container networks on the loopback network (net_view.h). */
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "host_syscall.h"
#include "net_view.h"

#define AF_INET_ 2
#define AF_INET6_ 10
#define IPPROTO_IPV6_ 41
#define IPV6_V6ONLY_ 26
#define O_RDONLY_ 0
#define O_CLOEXEC_ 02000000
#define AT_FDCWD_ (-100)

/* sockaddr_in: family, port (big-endian), address (big-endian);
 * sockaddr_in6: family, port, flowinfo, 16-byte address, scope id. */
struct in4 { uint16_t family, port; uint32_t addr; uint8_t zero[8]; };
struct in6 { uint16_t family, port; uint32_t flow; uint8_t addr[16]; uint32_t scope; };

static uint16_t be16(uint16_t v) { return (uint16_t)(v << 8 | v >> 8); }
static uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }

bool net_enabled(void)
{
    return g_payload_config.net_addr != 0;
}

/* The IPv4 address an IPv6 one stands for here: v4-mapped, or the
 * wildcard and loopback (0 and 127.0.0.1); 0 with *v4 false otherwise. */
static uint32_t v6_as_v4(const uint8_t a[16], bool *v4)
{
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    *v4 = true;
    bool is_mapped = true;
    for (int i = 0; i < 12; i++) is_mapped = is_mapped && a[i] == mapped[i];
    if (is_mapped) return (uint32_t)a[12] << 24 | (uint32_t)a[13] << 16 | (uint32_t)a[14] << 8 | a[15];
    bool zero = true;
    for (int i = 0; i < 15; i++) zero = zero && !a[i];
    if (zero && a[15] == 0) return 0;
    if (zero && a[15] == 1) return 0x7f000001u;
    *v4 = false;
    return 0;
}

static void v4_to_v6(uint32_t ip, uint8_t a[16])
{
    memset(a, 0, 10);
    a[10] = a[11] = 0xff;
    a[12] = (uint8_t)(ip >> 24);
    a[13] = (uint8_t)(ip >> 16);
    a[14] = (uint8_t)(ip >> 8);
    a[15] = (uint8_t)ip;
}

static bool peer(uint32_t ip)
{
    if (ip == g_payload_config.net_addr) return true;
    /* With --isolate the broker decides (it reads the file itself). */
    if (g_payload_config.isolate || !g_payload_config.net_peers[0]) return g_payload_config.isolate;
    long fd = host_syscall(__NR_openat, AT_FDCWD_, (long)g_payload_config.net_peers, O_RDONLY_ | O_CLOEXEC_, 0, 0, 0);
    if (fd < 0) return false;
    char text[4096];
    long n = host_syscall(__NR_read, fd, (long)text, sizeof(text), 0, 0, 0);
    host_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return n > 0 && net_peer_in(text, (unsigned long)n, ip);
}

/* A socket about to reach the pool: bound to the container's address
 * first when it is not bound yet (v6: IPv4-mapped, v6only off). */
static long source_bind(long fd, int family)
{
    unsigned char name[128];
    unsigned length = sizeof(name);
    if (host_syscall(__NR_getsockname, fd, (long)name, (long)&length, 0, 0, 0) < 0) return 0;
    uint32_t own = g_payload_config.net_addr;
    if (family == AF_INET_) {
        struct in4 a;
        memcpy(&a, name, sizeof(a));
        if (a.port || a.addr) return 0;
        memset(&a, 0, sizeof(a));
        a.family = AF_INET_;
        a.addr = be32(own);
        long rc = host_syscall(__NR_bind, fd, (long)&a, sizeof(a), 0, 0, 0);
        return rc == -EINVAL ? 0 : rc; /* (bound meanwhile) */
    }
    struct in6 a;
    memcpy(&a, name, sizeof(a));
    bool v4;
    if (a.port || v6_as_v4(a.addr, &v4) || !v4) return 0;
    int off = 0;
    host_syscall(__NR_setsockopt, fd, IPPROTO_IPV6_, IPV6_V6ONLY_, (long)&off, sizeof(off), 0);
    memset(&a, 0, sizeof(a));
    a.family = AF_INET6_;
    v4_to_v6(own, a.addr);
    long rc = host_syscall(__NR_bind, fd, (long)&a, sizeof(a), 0, 0, 0);
    return rc == -EINVAL ? 0 : rc;
}

long net_address(long number, long fd, const void *name, unsigned length, void *out, unsigned *out_length)
{
    *out_length = length;
    if (!name || length < 2 || length > 128) return 0;
    memcpy(out, name, length);
    uint16_t family;
    memcpy(&family, out, 2);
    bool v6 = family == AF_INET6_;
    if (!(family == AF_INET_ && length >= 8) && !(v6 && length >= 24)) return 0;
    uint32_t ip;
    uint16_t port;
    struct in4 a4;
    struct in6 a6;
    if (v6) {
        memcpy(&a6, out, sizeof(a6) <= length ? sizeof(a6) : length);
        bool v4;
        ip = v6_as_v4(a6.addr, &v4);
        if (!v4) return 0; /* a real IPv6 address: as it is */
        port = be16(a6.port);
    } else {
        memcpy(&a4, out, 8);
        ip = be32(a4.addr);
        port = be16(a4.port);
    }
    uint32_t own = g_payload_config.net_addr;
    bool bind = number == __NR_bind;
    long v6only = 0;
    if (bind) {
        if (ip == 0 || ip == 0x7f000001u) ip = own;
        else if (net_pool_address(ip) && ip != own) return -EADDRNOTAVAIL;
        if (ip == own && v6) {
            /* A v6-only socket on :: or ::1 (not an IPv4-mapped name):
             * the caller may need net_v6only_aside. */
            int on = 0;
            unsigned on_length = sizeof(on);
            if (a6.addr[10] != 0xff &&
                host_syscall(__NR_getsockopt, fd, IPPROTO_IPV6_, IPV6_V6ONLY_, (long)&on, (long)&on_length, 0) == 0 && on)
                v6only = 1;
            int off = 0;
            host_syscall(__NR_setsockopt, fd, IPPROTO_IPV6_, IPV6_V6ONLY_, (long)&off, sizeof(off), 0);
        }
    } else {
        if (ip == 0 || ip == 0x7f000001u) ip = own;
        else if (ip == NET_HOST_ALIAS) ip = 0x7f000001u;
        if (net_pool_address(ip)) {
            if (!peer(ip)) return -ECONNREFUSED;
            long rc = source_bind(fd, v6 ? AF_INET6_ : AF_INET_);
            if (rc < 0) return rc;
        }
    }
    if (net_pool_address(ip) && net_port_reserved(port)) return bind ? -EACCES : -ECONNREFUSED;
    if (net_pool_address(ip) && port && port < 1024) port = (uint16_t)(NET_PORT_BASE + port);
    if (v6) {
        v4_to_v6(ip, a6.addr);
        a6.port = be16(port);
        memcpy(out, &a6, 24);
    } else {
        a4.addr = be32(ip);
        a4.port = be16(port);
        memcpy(out, &a4, 8);
    }
    return v6only;
}

long net_v6only_aside(long fd, long rc)
{
    int on = 1;
    host_syscall(__NR_setsockopt, fd, IPPROTO_IPV6_, IPV6_V6ONLY_, (long)&on, sizeof(on), 0);
    struct in6 a;
    memset(&a, 0, sizeof(a));
    a.family = AF_INET6_;
    a.addr[15] = 1;
    long bound = host_syscall(__NR_bind, fd, (long)&a, sizeof(a), 0, 0, 0);
    return bound < 0 ? rc : 0;
}

void net_reverse(void *name, unsigned length)
{
    if (!name || length < 8) return;
    uint16_t family, port;
    memcpy(&family, name, 2);
    memcpy(&port, (char *)name + 2, 2);
    port = be16(port);
    uint32_t ip;
    if (family == AF_INET_) {
        memcpy(&ip, (char *)name + 4, 4);
        ip = be32(ip);
    } else if (family == AF_INET6_ && length >= 24) {
        bool v4;
        ip = v6_as_v4((const uint8_t *)name + 8, &v4);
        if (!v4) return;
    } else {
        return;
    }
    if (!net_pool_address(ip) || !net_port_reserved(port)) return;
    port = be16((uint16_t)(port - NET_PORT_BASE));
    memcpy((char *)name + 2, &port, 2);
}
