/* SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include "fd_table.h"

static struct fd_origin ro = {11, FD_ACCESS_RO}, rw = {22, FD_ACCESS_RW};
static void model_checks(void)
{
    struct fd_record slots[4], small_slots[1], copy_slots[4];
    struct fd_table t, small, copy;
    assert(fd_table_init(&t, slots, 4) == 0);
    assert(fd_table_init(&small, small_slots, 1) == 0);
    assert(fd_table_init(&copy, copy_slots, 4) == 0);
    assert(!fd_table_get(&t, 3));
    assert(fd_table_open(&t, 3, ro, 1) == 0);
    uint64_t generation = fd_table_get(&t, 3)->generation;
    uint64_t description = fd_table_get(&t, 3)->description;
    assert(fd_table_dup(&t, 3, 4, 0) == 0);
    assert(fd_table_get(&t, 4)->description == description);
    assert(fd_table_get(&t, 4)->origin.mount_id == 11);
    assert(fd_table_get(&t, 4)->origin.access == FD_ACCESS_RO);
    assert(!fd_table_get(&t, 4)->cloexec && fd_table_get(&t, 3)->cloexec);
    assert(fd_table_set_cloexec(&t, 3, 0) == 0);
    assert(fd_table_get(&t, 3)->generation == generation);
    assert(fd_table_dup(&t, 3, 3, 1) == 0);
    assert(!fd_table_get(&t, 3)->cloexec); /* dup2 no-op */
    assert(fd_table_open(&t, 5, rw, 0) == 0);
    assert(fd_table_get(&t, 5)->description != description);
    assert(fd_table_dup(&t, 3, 5, 1) == 0); /* dup3 replaces RW provenance */
    assert(fd_table_get(&t, 5)->origin.access == FD_ACCESS_RO);
    assert(fd_table_get(&t, 5)->description == description);
    assert(fd_table_dup(&t, 99, 5, 0) == 0); /* untracked inherited source */
    assert(fd_table_get(&t, 5)->origin.access == FD_ACCESS_UNKNOWN);
    assert(fd_table_get(&t, 5)->description == 0);
    assert(fd_table_get(&t, 5)->origin.mount_id == 0);
    assert(fd_table_set_cloexec(&t, 6, 1) == 0);
    assert(fd_table_get(&t, 6)->origin.access == FD_ACCESS_UNKNOWN);
    struct fd_record before[4];memcpy(before, slots, sizeof(slots));
    uint64_t serial = t.serial;
    assert(fd_table_open(&t, 1000000, rw, 0) == -ENOSPC);
    assert(fd_table_dup(&t, 3, 7, 0) == -ENOSPC);
    assert(fd_table_set_cloexec(&t, 7, 1) == -ENOSPC);
    assert(!memcmp(before, slots, sizeof(slots)) && t.serial == serial);
    assert(fd_table_copy(&small, &t) == -ENOSPC);
    assert(small.serial == 0 && small_slots[0].fd == -1);
    assert(fd_table_copy(&copy, &t) == 0);
    fd_table_close(&copy, 3);
    assert(fd_table_get(&t, 3) && !fd_table_get(&copy, 3));
    assert(fd_table_copy(&copy, &t) == -EBUSY);
    fd_table_exec(&t);
    assert(!fd_table_get(&t, 6) && fd_table_get(&t, 3) && fd_table_get(&t, 4));
    fd_table_close(&t, 3);
    assert(fd_table_open(&t, 3, rw, 0) == 0);
    assert(fd_table_get(&t, 3)->generation > generation);
    assert(fd_table_get(&t, 3)->description != description);
    assert(fd_table_get(&t, 4)->description == description);
    assert(fd_table_range(&t, 4, UINT_MAX, 1) == 0);
    assert(!fd_table_get(&t, 3)->cloexec && fd_table_get(&t, 4)->cloexec);
    assert(fd_table_range(&t, 5, 4, 0) == -EINVAL);
    fd_table_exec(&t);
    assert(fd_table_get(&t, 3) && !fd_table_get(&t, 4));
    assert(fd_table_range(&t, 0, UINT_MAX, 0) == 0);
    assert(!fd_table_get(&t, 3));
    assert(fd_table_open(&t, INT_MAX, rw, 0) == 0); /* sparse, no FD ceiling */
    t.serial = UINT64_MAX;
    memcpy(before, slots, sizeof(slots));
    assert(fd_table_open(&t, INT_MAX, ro, 0) == -EOVERFLOW);
    assert(fd_table_dup(&t, INT_MAX, 3, 0) == -EOVERFLOW);
    assert(!memcmp(before, slots, sizeof(slots)) && t.serial == UINT64_MAX);
    assert(fd_table_open(&t, -1, ro, 0) == -EINVAL);
    assert(fd_table_open(&t, 2, (struct fd_origin){1, 99}, 0) == -EINVAL);
    puts("PASS: mount provenance, aliases, unknown FDs, reuse, range, copy and failure atomicity");
}

static void kernel_checks(const char *self)
{
    struct fd_record slots[16], child_slots[16];
    struct fd_table t, child;
    assert(fd_table_init(&t, slots, 16) == 0);
    assert(fd_table_init(&child, child_slots, 16) == 0);
    int a = memfd_create("fd-model", MFD_CLOEXEC);
    assert(a >= 0 && fd_table_open(&t, a, rw, 1) == 0);
    int b = dup(a);
    assert(b >= 0 && fd_table_dup(&t, a, b, 0) == 0);
    assert(fcntl(a, F_GETFD) == FD_CLOEXEC && fcntl(b, F_GETFD) == 0);
    assert(write(a, "AB", 2) == 2 && lseek(b, 0, SEEK_CUR) == 2);
    assert(fd_table_get(&t, a)->description == fd_table_get(&t, b)->description);
    int c = fcntl(a, F_DUPFD_CLOEXEC, 20);
    assert(c >= 20 && fd_table_dup(&t, a, c, 1) == 0);
    assert(fcntl(c, F_GETFD) == FD_CLOEXEC);
    uint64_t old = fd_table_get(&t, c)->generation;
    assert(dup3(b, c, 0) == c && fd_table_dup(&t, b, c, 0) == 0);
    assert(fcntl(c, F_GETFD) == 0 && fd_table_get(&t, c)->generation > old);
    /* Failed kernel calls are never published as metadata events. */
    old = t.serial;
    assert(dup3(-1, c, 0) == -1 && errno == EBADF);
    assert(t.serial == old && fcntl(c, F_GETFD) == 0);
    assert(fcntl(c, F_SETFD, FD_CLOEXEC) == 0);
    assert(fd_table_set_cloexec(&t, c, 1) == 0);
    assert(fd_table_copy(&child, &t) == 0);
    pid_t pid = fork();assert(pid >= 0);
    if (!pid) {
        assert(close(b) == 0);fd_table_close(&child, b);
        assert(!fd_table_get(&child, b) && fd_table_get(&t, b));
        assert(fcntl(a, F_SETFD, 0) == 0);
        assert(fd_table_set_cloexec(&child, a, 0) == 0);
        fd_table_exec(&child);
        assert(fd_table_get(&child, a) && !fd_table_get(&child, c));
        char keep[24], gone[24];snprintf(keep, sizeof(keep), "%d", a);snprintf(gone, sizeof(gone), "%d", c);
        execl(self, self, "--after-exec", keep, gone, (char *)NULL);
        _exit(100);
    }
    int status;assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(fcntl(b, F_GETFD) == 0 && fcntl(a, F_GETFD) == FD_CLOEXEC);
    assert(fd_table_get(&t, b) && fd_table_get(&t, a)->cloexec);
    assert(close(c) == 0);fd_table_close(&t, c);
    assert(fcntl(a, F_DUPFD, c) == c && fd_table_dup(&t, a, c, 0) == 0);
    assert(fcntl(c, F_GETFD) == fd_table_get(&t, c)->cloexec);
    assert(close(a) == 0);fd_table_close(&t, a);
    assert(close(b) == 0);fd_table_close(&t, b);
    assert(close(c) == 0);fd_table_close(&t, c);
    puts("PASS: native dup/dup3/fcntl, shared offset, fork independence and actual exec CLOEXEC");
}
int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--after-exec")) {
        assert(fcntl(atoi(argv[2]), F_GETFD) == 0);
        assert(fcntl(atoi(argv[3]), F_GETFD) == -1 && errno == EBADF);
        return 0;
    }
    model_checks();kernel_checks(argv[0]);return 0;
}
