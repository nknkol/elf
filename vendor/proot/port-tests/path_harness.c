/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host adapter for semantic tests: shared binding core, no proc emulation.
 * Production bind setup and FD ownership are not implemented by this harness.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "path/resolve_core.h"
#include "path/binding_core.h"
typedef struct { BindingTable table; } Fixture;
static int map(void *opaque, const char *guest, char *host)
{
    Fixture *f = opaque;
    return binding_table_map(&f->table, GUEST, guest, host);
}
static int lookup(void *opaque, Finality final, unsigned int level,
                  const char *guest, char *host)
{
    struct stat st;
    (void)level;
    int rc = map(opaque, guest, host);
    if (rc < 0) return rc;
    if (lstat(host, &st) < 0) return IS_FINAL(final) ? 0 : -errno;
    if (!IS_FINAL(final) && !S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode))
        return -ENOTDIR;
    return S_ISLNK(st.st_mode) ? 1 : 0;
}
static int read_link(void *opaque, const char *p, char *out, size_t n)
{
    (void)opaque;
    ssize_t rc = readlink(p, out, n);
    return rc < 0 ? -errno : (int)rc;
}
static int reverse(void *opaque, char *path, const char *referrer)
{
    (void)opaque; (void)path; (void)referrer;
    /* Ordinary guest symlink contents are already in the guest namespace. */
    return 0;
}
static int proc_link(void *opaque, char *out, const char *p, const char *c, Comparison cmp)
{
    (void)opaque; (void)out; (void)p; (void)c; (void)cmp;
    return -EOPNOTSUPP;
}
static int fd_guest(void *opaque, int fd, char *guest)
{
    Fixture *f = opaque;
    char link[64], host[PATH_MAX]; struct stat st;
    if (fstat(fd, &st) < 0) return -errno;
    if (!S_ISDIR(st.st_mode)) return -ENOTDIR;
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    int rc = read_link(opaque, link, host, sizeof(host)-1);
    if (rc < 0) return rc;
    host[rc] = 0;
    return binding_table_map(&f->table, HOST, host, guest);
}
int main(int argc, char **argv)
{
    if (argc != 8) return 2;
    PathBinding bindings[] = {{"/mnt", argv[2]}};
    Fixture fixture = {{argv[1], bindings, 1}};
    if (binding_table_validate(&fixture.table) < 0) return 2;
    const PathOps ops = {lookup, read_link, reverse, proc_link};
    PathResolver resolver = {{&fixture, &ops}, argv[3], fd_guest, map};
    int fd = AT_FDCWD;
    if (strcmp(argv[6], "-") != 0) {
        fd = open(argv[6], O_RDONLY | O_CLOEXEC);
        if (fd < 0) { perror("open fixture fd"); return 2; }
        if (strcmp(argv[7], "-") != 0 && rename(argv[6], argv[7]) < 0) {
            perror("rename fixture directory"); return 2;
        }
    }
    char guest[PATH_MAX], host[PATH_MAX];
    int rc = resolve_path_core(&resolver, fd, argv[4], atoi(argv[5]), guest, host);
    printf("%d\n", rc);
    if (rc == 0) {
        printf("%s\n%s\n", guest, host);
        struct stat st;
        int final_rc = lstat(host, &st);
        printf("%d\n", final_rc < 0 ? -errno : 0);
    }
    if (fd != AT_FDCWD) close(fd);
    return 0;
}
