/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include "fd_table.h"

#define EMPTY ((struct fd_record){.fd = -1})

int fd_table_init(struct fd_table *t, struct fd_record *slots, size_t capacity)
{
    if (!t || !slots || !capacity) return -EINVAL;
    *t = (struct fd_table){slots, capacity, 0, 0, 0, capacity, 0};
    return 0;
}

int fd_table_limit(struct fd_table *t, size_t limit)
{
    if (!t || !limit || limit > t->capacity) return -EINVAL;
    t->limit = limit;
    return 0;
}

int fd_table_direct(struct fd_table *t)
{
    if (!t || t->live || t->serial) return -EBUSY;
    t->direct = 1;
    t->used = 0;
    return 0;
}

void fd_table_reset(struct fd_table *t)
{
    t->serial = t->used = t->live = 0;
}

size_t fd_table_live(const struct fd_table *t) { return t->live; }

size_t fd_table_free(const struct fd_table *t) { return t->live < t->limit ? t->limit - t->live : 0; }

/* Direct tables: slots below `used` are initialized; reaching slot n
 * initializes the ones before it. */
static struct fd_record *direct_slot(struct fd_table *t, int fd, int extend)
{
    if (fd < 0 || (size_t)fd >= t->capacity) return NULL;
    if ((size_t)fd >= t->used) {
        if (!extend) return NULL;
        for (size_t i = t->used; i <= (size_t)fd; i++) t->slots[i] = EMPTY;
        t->used = (size_t)fd + 1;
    }
    return &t->slots[fd];
}

static struct fd_record *find(const struct fd_table *t, int fd)
{
    if (fd < 0) return NULL;
    if (t->direct) {
        struct fd_record *slot = direct_slot((struct fd_table *)t, fd, 0);
        return slot && slot->fd == fd ? slot : NULL;
    }
    for (size_t i = 0; i < t->used; i++)
        if (t->slots[i].fd == fd) return &t->slots[i];
    return NULL;
}

const struct fd_record *fd_table_get(const struct fd_table *t, int fd) { return find(t, fd); }

static struct fd_record *destination(struct fd_table *t, int fd)
{
    if (t->direct) return direct_slot(t, fd, 1);
    struct fd_record *empty = NULL;
    for (size_t i = 0; i < t->used; i++) {
        if (t->slots[i].fd == fd) return &t->slots[i];
        if (t->slots[i].fd < 0 && !empty) empty = &t->slots[i];
    }
    if (!empty && t->used < t->capacity) {
        empty = &t->slots[t->used++];
        *empty = EMPTY;
    }
    return empty;
}

static void clear(struct fd_table *t, struct fd_record *slot)
{
    if (slot->fd >= 0) t->live--;
    *slot = EMPTY;
}

static int assign(struct fd_table *t, int fd, struct fd_record value, int new_description)
{
    if (fd < 0) return -EINVAL;
    struct fd_record *slot = destination(t, fd);
    if (!slot || (slot->fd < 0 && t->live >= t->limit)) return -ENOSPC;
    if (t->serial == UINT64_MAX) return -EOVERFLOW;
    value.fd = fd;
    value.generation = ++t->serial;
    if (new_description) value.description = value.generation;
    if (slot->fd < 0) t->live++;
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

int fd_table_open_pipe_writer(struct fd_table *t, int fd, int cloexec)
{
    if(cloexec!=0 && cloexec!=1)return -EINVAL;
    return assign(t,fd,(struct fd_record){.cloexec=cloexec,.pipe_writer=1},1);
}

int fd_table_grant_stream(struct fd_table *t, int fd)
{
    if (fd < 0) return -EINVAL;
    struct fd_record *slot = find(t, fd);
    if (!slot) return -ENOENT;
    slot->stream_reader = 1;
    return 0;
}

int fd_table_grant_passed(struct fd_table *t, int fd)
{
    if (fd < 0) return -EINVAL;
    struct fd_record *slot = find(t, fd);
    if (!slot) return -ENOENT;
    slot->passed = 1;
    return 0;
}

int fd_table_grant_local_writer(struct fd_table *t, int fd)
{
    if (fd < 0) return -EINVAL;
    struct fd_record *slot = find(t, fd);
    if (!slot) return -ENOENT;
    slot->local_writer = 1;
    return 0;
}

int fd_table_import_unknown(struct fd_table *t, int fd, int cloexec)
{
    if (cloexec != 0 && cloexec != 1) return -EINVAL;
    return assign(t, fd, (struct fd_record){.cloexec = cloexec}, 0);
}

int fd_table_dup(struct fd_table *t, int source, int target, int cloexec)
{
    if (source < 0 || target < 0 || (cloexec != 0 && cloexec != 1)) return -EINVAL;
    if (source == target) return 0;
    const struct fd_record *src = find(t, source);
    /* Copy before assignment: target may overwrite an existing source alias. */
    struct fd_record value = src ? *src : (struct fd_record){0};
    value.cloexec = cloexec;
    return assign(t, target, value, 0);
}

int fd_table_set_cloexec(struct fd_table *t, int fd, int cloexec)
{
    if (fd < 0 || (cloexec != 0 && cloexec != 1)) return -EINVAL;
    struct fd_record *slot = find(t, fd);
    if (slot) {
        slot->cloexec = cloexec;
        return 0;
    }
    /* F_SETFD on an inherited, untracked FD reveals no mount permission. */
    if (!destination(t, fd)) return -ENOSPC;
    return assign(t, fd, (struct fd_record){.cloexec = cloexec}, 0);
}

void fd_table_close(struct fd_table *t, int fd)
{
    struct fd_record *slot = find(t, fd);
    if (slot) clear(t, slot);
}

int fd_table_close_generation(struct fd_table *t, int fd, uint64_t generation)
{
    if (!t || fd < 0) return -EINVAL;
    struct fd_record *slot = find(t, fd);
    if (!slot) return 0;
    if (!generation || slot->generation != generation) return -ESTALE;
    clear(t, slot);
    return 0;
}

int fd_table_range(struct fd_table *t, unsigned first, unsigned last, int cloexec)
{
    if (first > last || (cloexec != 0 && cloexec != 1)) return -EINVAL;
    for (size_t i = 0; i < t->used; i++) {
        struct fd_record *slot = &t->slots[i];
        if (slot->fd < 0 || (unsigned)slot->fd < first || (unsigned)slot->fd > last) continue;
        if (cloexec) slot->cloexec = 1;
        else clear(t, slot);
    }
    return 0;
}

void fd_table_exec(struct fd_table *t)
{
    for (size_t i = 0; i < t->used; i++) {
        struct fd_record *slot = &t->slots[i];
        if (slot->fd >= 0 && slot->cloexec) clear(t, slot);
        else slot->pipe_writer = slot->stream_reader = slot->local_writer = slot->passed = 0;
    }
}

int fd_table_copy(struct fd_table *dst, const struct fd_table *src)
{
    if (dst == src) return -EINVAL;
    if (dst->live) return -EBUSY;
    if (src->live > dst->limit) return -ENOSPC;
    /* Never reuse generations from a previously used destination table. */
    if (dst->serial) return -EBUSY;
    if (dst->direct) {
        /* FD n stays in slot n; a compact source may name FDs beyond. */
        for (size_t i = 0; i < src->used; i++)
            if (src->slots[i].fd >= 0 && (size_t)src->slots[i].fd >= dst->capacity) return -ENOSPC;
        dst->used = 0;
        for (size_t i = 0; i < src->used; i++)
            if (src->slots[i].fd >= 0) *direct_slot(dst, src->slots[i].fd, 1) = src->slots[i];
    } else {
        size_t count = 0;
        for (size_t i = 0; i < src->used; i++)
            if (src->slots[i].fd >= 0) dst->slots[count++] = src->slots[i];
        dst->used = count;
    }
    dst->live = src->live;
    dst->serial = src->serial;
    return 0;
}
