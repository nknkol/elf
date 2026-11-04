/* One process holding many FDs (test_many_blocked.py): a pipe's ends
 * duplicated N times (the soft RLIMIT_NOFILE raised to the hard one), a
 * write through the highest duplicate read back through the first.
 * Prints "fds N/N ok" or what failed. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int want = argc > 1 ? atoi(argv[1]) : 10000;
    struct rlimit limit;
    getrlimit(RLIMIT_NOFILE, &limit);
    limit.rlim_cur = limit.rlim_max;
    setrlimit(RLIMIT_NOFILE, &limit);
    if (limit.rlim_max != RLIM_INFINITY && (long)limit.rlim_max < want + 64)
        want = (int)limit.rlim_max - 64;
    int ends[2];
    if (pipe(ends)) { printf("pipe: %s\n", strerror(errno)); return 1; }
    int *fds = calloc((size_t)want, sizeof(int)), made = 0, last = -1;
    for (; made < want; made++) {
        fds[made] = dup(ends[1]);
        if (fds[made] < 0) { printf("dup %d: %s\n", made, strerror(errno)); break; }
        last = fds[made];
    }
    char in = 0;
    int ok = made == want && write(last, "x", 1) == 1 && read(ends[0], &in, 1) == 1 && in == 'x';
    for (int i = 0; i < made; i++) close(fds[i]);
    printf("fds %d/%d %s (highest %d)\n", made, want, ok ? "ok" : "failed", last);
    return 0;
}
