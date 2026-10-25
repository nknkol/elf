/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "fd_table.h"

int fd_table_init(struct fd_table *t, struct fd_record *slots, size_t capacity)
{
    if (!t || !slots || !capacity) return -EINVAL;
    *t = (struct fd_table){slots, capacity, 0};
    for (size_t i = 0; i < capacity; i++) slots[i] = (struct fd_record){.fd = -1};
    return 0;
}

const struct fd_record *fd_table_get(const struct fd_table *t, int fd)
{
    if (fd < 0) return NULL;
    for (size_t i = 0; i < t->capacity; i++)
        if (t->slots[i].fd == fd) return &t->slots[i];
    return NULL;
}

static struct fd_record *destination(struct fd_table *t, int fd)
{
    struct fd_record *empty = NULL;
    for (size_t i = 0; i < t->capacity; i++) {
        if (t->slots[i].fd == fd) return &t->slots[i];
        if (t->slots[i].fd < 0 && !empty) empty = &t->slots[i];
    }
    return empty;
}

static int assign(struct fd_table *t, int fd, struct fd_record value, int new_description)
{
    if (fd < 0) return -EINVAL;
    struct fd_record *slot = destination(t, fd);
    if (!slot) return -ENOSPC;
    if (t->serial == UINT64_MAX) return -EOVERFLOW;
    value.fd = fd;
    value.generation = ++t->serial;
    if (new_description) value.description = value.generation;
    *slot = value;
    return 0;
}

int fd_table_open(struct fd_table *t, int fd, struct fd_origin origin, int cloexec)
{
    if (origin.access < FD_ACCESS_UNKNOWN || origin.access > FD_ACCESS_RW ||
        (cloexec != 0 && cloexec != 1)) return -EINVAL;
    if (origin.access == FD_ACCESS_UNKNOWN) origin.mount_id = 0;
    return assign(t, fd, (struct fd_record){.cloexec = cloexec, .origin = origin}, 1);
}

int fd_table_dup(struct fd_table *t, int source, int target, int cloexec)
{
    if (source < 0 || target < 0 || (cloexec != 0 && cloexec != 1)) return -EINVAL;
    if (source == target) return 0;
    const struct fd_record *src = fd_table_get(t, source);
    /* Copy before assignment: target may overwrite an existing source alias. */
    struct fd_record value = src ? *src : (struct fd_record){0};
    value.cloexec = cloexec;
    return assign(t, target, value, 0);
}

int fd_table_set_cloexec(struct fd_table *t, int fd, int cloexec)
{
    if (fd < 0 || (cloexec != 0 && cloexec != 1)) return -EINVAL;
    struct fd_record *slot = destination(t, fd);
    if (!slot) return -ENOSPC;
    if (slot->fd == fd) {
        slot->cloexec = cloexec;
        return 0;
    }
    /* F_SETFD on an inherited, untracked FD reveals no mount permission. */
    return assign(t, fd, (struct fd_record){.cloexec = cloexec}, 0);
}

void fd_table_close(struct fd_table *t, int fd)
{
    if (fd < 0) return;
    for (size_t i = 0; i < t->capacity; i++)
        if (t->slots[i].fd == fd) t->slots[i] = (struct fd_record){.fd = -1};
}

int fd_table_range(struct fd_table *t, unsigned first, unsigned last, int cloexec)
{
    if (first > last || (cloexec != 0 && cloexec != 1)) return -EINVAL;
    for (size_t i = 0; i < t->capacity; i++) {
        struct fd_record *slot = &t->slots[i];
        if (slot->fd < 0 || (unsigned)slot->fd < first || (unsigned)slot->fd > last) continue;
        if (cloexec) slot->cloexec = 1;
        else *slot = (struct fd_record){.fd = -1};
    }
    return 0;
}

void fd_table_exec(struct fd_table *t)
{
    for (size_t i = 0; i < t->capacity; i++)
        if (t->slots[i].fd >= 0 && t->slots[i].cloexec)
            t->slots[i] = (struct fd_record){.fd = -1};
}

int fd_table_copy(struct fd_table *dst, const struct fd_table *src)
{
    if (dst == src) return -EINVAL;
    for (size_t i = 0; i < dst->capacity; i++)
        if (dst->slots[i].fd >= 0) return -EBUSY;
    size_t count = 0;
    for (size_t i = 0; i < src->capacity; i++) count += src->slots[i].fd >= 0;
    if (count > dst->capacity) return -ENOSPC;
    /* Never reuse generations from a previously used destination table. */
    if (dst->serial) return -EBUSY;
    count = 0;
    for (size_t i = 0; i < src->capacity; i++)
        if (src->slots[i].fd >= 0) dst->slots[count++] = src->slots[i];
    dst->serial = src->serial;
    return 0;
}
