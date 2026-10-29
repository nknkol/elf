/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_RECEIVE_H
#define ELF_FD_RECEIVE_H
#include <stddef.h>
#include "fd_table.h"
/* Table exclusion for threads sharing it. The kernel receive runs unlocked;
 * capacity is reserved before it and the reservation released after import.
 * Callbacks are assigned at run time (no static function-pointer tables). */
struct fd_receive_sync {
    void *context;
    void (*lock)(void *);
    void (*unlock)(void *);
    size_t *reserved;
};
long fd_receive_message(struct fd_table *, long [6], const struct fd_receive_sync *);
long fd_receive_messages(struct fd_table *, long [6], const struct fd_receive_sync *);
#endif
