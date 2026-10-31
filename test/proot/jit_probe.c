/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Executable memory under the loader, as JITs use it. Prints one line per
 * case: "<case> <value>", the generated code's return value or -errno. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

static const unsigned code42[] = {0x52800540 /* mov w0, #42 */, 0xd65f03c0 /* ret */};

/* Runs the code in a child: a crash is reported, not fatal. */
static void run(const char *label, void *p)
{
    __builtin___clear_cache((char *)p, (char *)p + 64);
    fflush(stdout);
    pid_t pid = fork();
    if (!pid) {
        printf("%s %d\n", label, ((int (*)(void))p)());
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("%s signal%d\n", label, WTERMSIG(status));
}

int main(void)
{
    void *a = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(a, code42, sizeof code42);
    if (mprotect(a, 4096, PROT_READ | PROT_EXEC)) printf("rw-rx %d\n", -errno); else run("rw-rx", a);
    void *b = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (b == MAP_FAILED) printf("rwx %d\n", -errno);
    else { memcpy(b, code42, sizeof code42); run("rwx", b); }
    /* Patched after it ran: RX -> RW -> RX. */
    if (!mprotect(a, 4096, PROT_READ | PROT_WRITE)) {
        ((unsigned *)a)[0] = 0x52800f60; /* mov w0, #123 */
        if (mprotect(a, 4096, PROT_READ | PROT_EXEC)) printf("patched %d\n", -errno); else run("patched", a);
    }
    /* Dual mapping of a memfd: refused (natively too), never a stale copy. */
    int fd = memfd_create("jit", 0);
    if (ftruncate(fd, 4096)) return 1;
    void *w = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    void *x = mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    if (x == MAP_FAILED) printf("memfd-shared-exec %d\n", -errno);
    else { memcpy(w, code42, sizeof code42); run("memfd-shared-exec", x); }
    /* A private executable mapping of a file still works (hooked copy). */
    const char *dir = getenv("JIT_DIR");
    char buf[512];
    snprintf(buf, sizeof buf, "%s/jit-code", dir ? dir : ".");
    FILE *f = fopen(buf, "w");
    if (!f) { printf("file-private-exec %d\n", -errno); return 0; }
    fwrite(code42, sizeof code42, 1, f);
    fclose(f);
    int file = open(buf, 0);
    void *y = mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, file, 0);
    if (y == MAP_FAILED) printf("file-private-exec %d\n", -errno); else run("file-private-exec", y);
    return 0;
}
