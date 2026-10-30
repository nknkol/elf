/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include "path/resolve_core.h"
int resolve_path_core(PathResolver *ctx, int dirfd, const char *path,
                      bool follow, char guest[PATH_MAX], char host[PATH_MAX])
{
    int rc;
    if (!ctx || !path || !guest || !host || guest == host ||
        !ctx->guest_to_host)
        return -EINVAL;
    char (*scratch)[PATH_MAX] = ctx->scratch ? ctx->scratch : __builtin_alloca(2 * PATH_MAX);
    char *base = scratch[0], *joined = scratch[1];
    /* AT_EMPTY_PATH belongs to syscall/FD handling, not pathname walking. */
    if (!*path)
        return -ENOENT;
    if (*path == '/')
        strcpy(base, "/");
    else if (dirfd == AT_FDCWD) {
        if (!ctx->cwd || ctx->cwd[0] != '/')
            return -EINVAL;
        if (strnlen(ctx->cwd, PATH_MAX) >= PATH_MAX)
            return -ENAMETOOLONG;
        strcpy(base, ctx->cwd);
    } else {
        if (!ctx->dirfd_guest)
            return -EBADF;
        rc = ctx->dirfd_guest(ctx->path.opaque, dirfd, base);
        if (rc < 0)
            return rc;
        if (strnlen(base, PATH_MAX) >= PATH_MAX)
            return -ENAMETOOLONG;
        if (base[0] != '/')
            return -ENOTDIR;
    }
    rc = join_paths(2, joined, base, path);
    if (rc < 0)
        return rc;
    strcpy(guest, "/");
    rc = canonicalize_core(&ctx->path, joined, follow, guest, 0);
    if (rc < 0)
        return rc;
    return ctx->guest_to_host(ctx->path.opaque, guest, host);
}
