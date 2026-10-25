/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <limits.h>
#include "fd_snapshot.h"

#define SNAPSHOT_MAGIC UINT64_C(0x31534446464c45)
#define SNAPSHOT_VERSION 1
static uint64_t get_word(const unsigned char *p)
{
    uint64_t word = 0;
    for (unsigned i = 0; i < 8; i++) word |= (uint64_t)p[i] << (8 * i);
    return word;
}
static void put_word(unsigned char *p, uint64_t word)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(word >> (8 * i));
}

int fd_snapshot_size(const struct fd_table *t, size_t *bytes)
{
    if (!bytes) return -EINVAL;
    size_t size = FD_SNAPSHOT_HEADER_BYTES;
    for (size_t i = 0; i < t->capacity; i++) {
        if (t->slots[i].fd < 0 || t->slots[i].cloexec) continue;
        if (size > SIZE_MAX - FD_SNAPSHOT_ENTRY_BYTES) return -EOVERFLOW;
        size += FD_SNAPSHOT_ENTRY_BYTES;
    }
    *bytes = size;
    return 0;
}

int fd_snapshot_export(const struct fd_table *t, void *buffer, size_t capacity,
                       size_t *written)
{
    if (!buffer || !written) return -EINVAL;
    size_t size;
    int rc = fd_snapshot_size(t, &size);
    if (rc) return rc;
    if (capacity < size) return -ENOSPC;
    unsigned char *p = buffer;
    put_word(p, SNAPSHOT_MAGIC);
    put_word(p + 8, SNAPSHOT_VERSION);
    put_word(p + 16, t->serial);
    put_word(p + 24, (size - FD_SNAPSHOT_HEADER_BYTES) / FD_SNAPSHOT_ENTRY_BYTES);
    p += FD_SNAPSHOT_HEADER_BYTES;
    for (size_t i = 0; i < t->capacity; i++) {
        const struct fd_record *r = &t->slots[i];
        if (r->fd < 0 || r->cloexec) continue;
        put_word(p, (unsigned)r->fd);
        put_word(p + 8, 0);
        put_word(p + 16, r->generation);
        put_word(p + 24, r->description);
        put_word(p + 32, r->origin.mount_id);
        put_word(p + 40, r->origin.access);
        p += FD_SNAPSHOT_ENTRY_BYTES;
    }
    *written = size;
    return 0;
}

int fd_snapshot_import(struct fd_table *t, const void *buffer, size_t bytes)
{
    if (!buffer || bytes < FD_SNAPSHOT_HEADER_BYTES) return -EINVAL;
    if (t->serial) return -EBUSY;
    for (size_t i = 0; i < t->capacity; i++)
        if (t->slots[i].fd >= 0) return -EBUSY;
    const unsigned char *p = buffer;
    if (get_word(p) != SNAPSHOT_MAGIC || get_word(p + 8) != SNAPSHOT_VERSION)
        return -EINVAL;
    uint64_t serial = get_word(p + 16), count = get_word(p + 24);
    if ((bytes - FD_SNAPSHOT_HEADER_BYTES) % FD_SNAPSHOT_ENTRY_BYTES ||
        count != (bytes - FD_SNAPSHOT_HEADER_BYTES) / FD_SNAPSHOT_ENTRY_BYTES)
        return -EINVAL;
    if (count > t->capacity) return -ENOSPC;
    p += FD_SNAPSHOT_HEADER_BYTES;
    /* Validate before touching any destination slot. Bounded O(n^2) checking
     * avoids allocating a second table or storing untrusted pointer fields. */
    for (size_t i = 0; i < (size_t)count; i++) {
        const unsigned char *r = p + i * FD_SNAPSHOT_ENTRY_BYTES;
        uint64_t fd = get_word(r), flags = get_word(r + 8);
        uint64_t generation = get_word(r + 16), description = get_word(r + 24);
        uint64_t mount = get_word(r + 32), access = get_word(r + 40);
        if (fd > INT_MAX || flags || !generation || generation > serial ||
            description > generation || access > FD_ACCESS_RW ||
            (access != FD_ACCESS_UNKNOWN && !description) ||
            (access == FD_ACCESS_UNKNOWN && mount)) return -EINVAL;
        for (size_t j = 0; j < i; j++) {
            const unsigned char *other = p + j * FD_SNAPSHOT_ENTRY_BYTES;
            if (get_word(other) == fd || get_word(other + 16) == generation)
                return -EINVAL;
            if ((description && get_word(other + 16) == description &&
                 get_word(other + 24) != description) ||
                (get_word(other + 24) == generation && description != generation))
                return -EINVAL;
            if (description && get_word(other + 24) == description &&
                (get_word(other + 32) != mount || get_word(other + 40) != access))
                return -EINVAL;
        }
    }
    for (size_t i = 0; i < (size_t)count; i++) {
        const unsigned char *r = p + i * FD_SNAPSHOT_ENTRY_BYTES;
        t->slots[i] = (struct fd_record){
            .fd = (int)get_word(r), .cloexec = 0,
            .generation = get_word(r + 16), .description = get_word(r + 24),
            .origin = {get_word(r + 32), (enum fd_access)get_word(r + 40)}
        };
    }
    t->serial = serial;
    return 0;
}
