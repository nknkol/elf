/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ELF_FD_REGISTRY_H
#define ELF_FD_REGISTRY_H
#include "fd_clone.h"
struct fd_task_handle { size_t slot; uint64_t generation; };
struct fd_task_slot {
    uint64_t generation;
    unsigned state;
    size_t table_slot;
    struct fd_clone clone;
};
struct fd_table_slot { struct fd_table table; size_t owners; };
struct fd_registry {
    struct fd_task_slot *tasks;
    struct fd_table_slot *tables;
    size_t task_count, table_count;
    uint64_t serial;
};
/* Metadata ownership core, NOT a runtime synchronization scheme. Caller must
 * serialize every operation (including lookup and borrowed table use), keep
 * source stable during copying, and supply inherited shared storage for all
 * objects/records. Never hold that exclusion across kernel clone or callbacks.
 * Entries are reserved before clone; publication does not allocate. */
int fd_registry_init(struct fd_registry *, struct fd_task_slot *, size_t,
                     struct fd_table_slot *, size_t, struct fd_record *, size_t);
int fd_registry_create(struct fd_registry *, struct fd_task_handle *);
int fd_registry_clone(struct fd_registry *, struct fd_task_handle parent,
                      enum fd_clone_mode, struct fd_task_handle *);
int fd_registry_publish(struct fd_registry *, struct fd_task_handle, long tid);
int fd_registry_find(struct fd_registry *, long tid, struct fd_task_handle *);
/* Borrowed table for a valid reservation/live owner; never cache across retire.
 * Unknown/reused handles return NULL. Generations are registry-local. */
struct fd_table *fd_registry_table(struct fd_registry *, struct fd_task_handle);
int fd_registry_cancel(struct fd_registry *, struct fd_task_handle);
/* Caller establishes task death AND all notification/readers are finished.
 * TID alone never authorizes retirement; PID namespaces are not supported here.
 * No liveness probing, automatic exit interception or exec handoff is provided. */
int fd_registry_retire(struct fd_registry *, struct fd_task_handle);
#endif
