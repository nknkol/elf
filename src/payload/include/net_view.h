/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Container networks (docs/OCI.md, compose networks): without network
 * namespaces every container gets an address of its own on the loopback
 * network (Linux routes all of 127.0.0.0/8 there; docker gives them out
 * of NET_POOL) and the payload moves the guest's sockets onto it:
 *  - bind to the wildcard or to 127.0.0.1 binds the container's address
 *    (so two containers can each listen on port 80); bind to another
 *    address of the pool is EADDRNOTAVAIL;
 *  - connect/sendto to 127.0.0.1 (or the wildcard) reach the container
 *    itself, as localhost in a network namespace; NET_HOST_ALIAS reaches
 *    the host's 127.0.0.1 (host.docker.internal); an address of the pool
 *    is reachable when it is the container's own or in its peers file
 *    (containers sharing a network), else ECONNREFUSED; a socket that
 *    reaches the pool is first bound to the container's address, so peers
 *    see where it comes from;
 *  - ports below 1024 of a pool address are ports NET_PORT_BASE + p on
 *    the host (an unprivileged process cannot bind them), shown as p in
 *    every address the guest gets back; the guest cannot use those host
 *    ports itself (bind EACCES, connect ECONNREFUSED), so the mapping
 *    has no collisions and reads back unambiguously.
 * IPv6 sockets take the same through IPv4-mapped addresses (:: and ::1
 * are the container's address). Without --isolate this is a view, not a
 * boundary; with it the broker refuses binds to other pool addresses and
 * connects to pool addresses that are not peers. */
#ifndef NET_VIEW_H
#define NET_VIEW_H
#include <stdbool.h>
#include <stdint.h>

#define NET_POOL 0x7f800000u        /* 127.128.0.0/9 */
#define NET_POOL_MASK 0xff800000u
#define NET_HOST_ALIAS 0x7f7f0001u  /* 127.127.0.1: the host's 127.0.0.1 */
#define NET_PORT_BASE 61000u        /* above the ephemeral ports */

static inline bool net_pool_address(uint32_t ip) { return (ip & NET_POOL_MASK) == NET_POOL; }

/* The host ports that stand for ports 1..1023 of a pool address. */
static inline bool net_port_reserved(uint32_t port) { return port > NET_PORT_BASE && port < NET_PORT_BASE + 1024; }

/* Whether ip (host order) is in text, the peers file's content (one
 * dotted address per line); the payload and the broker read it. */
static inline bool net_peer_in(const char *text, unsigned long n, uint32_t ip)
{
    unsigned long i = 0;
    while (i < n) {
        uint32_t value = 0, part = 0;
        int dots = 0, digits = 0;
        bool ok = true;
        for (; i < n && text[i] != '\n'; i++) {
            char c = text[i];
            if (c >= '0' && c <= '9') {
                part = part * 10 + (uint32_t)(c - '0');
                digits++;
                if (part > 255) ok = false;
            } else if (c == '.' && digits) {
                value = value << 8 | part;
                part = 0;
                digits = 0;
                dots++;
            } else {
                ok = false;
            }
        }
        i++;
        if (ok && dots == 3 && digits && (value << 8 | part) == ip) return true;
    }
    return false;
}

bool net_enabled(void);

/* bind, connect, sendto or sendmsg of fd to the address name/length:
 * 0 with out and out_length to use instead (or the same address), or
 * -errno. out holds 128 bytes. */
long net_address(long number, long fd, const void *name, unsigned length, void *out, unsigned *out_length);

/* An address the kernel gave the guest (getsockname, getpeername, accept,
 * recvfrom, recvmsg): ports of pool addresses shown as the guest's. */
void net_reverse(void *name, unsigned length);

#endif
