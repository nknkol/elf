/* Many threads at once in calls the payload handles, each blocked (openat
 * of a FIFO with no writer yet): test_many_blocked.py. Each thread runs on
 * a small stack filled with a pattern, as a goroutine's; afterwards the
 * deepest use below the point of the call is measured.
 *
 * Prints "opened N/T" (threads whose open succeeded), the distinct errors,
 * and "deepest B" (bytes of thread stack used, the probe's own frames
 * included). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define STACK (64 * 1024)
#define PATTERN 0xa5

struct worker {
    pthread_t thread;
    char path[64];
    unsigned char *stack;
    int result;
};

static void *blocked_open(void *arg)
{
    struct worker *w = arg;
    int fd = open(w->path, O_RDONLY);
    w->result = fd >= 0 ? 0 : errno;
    if (fd >= 0)
        close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    int count = argc > 2 ? atoi(argv[2]) : 80;
    const char *dir = argc > 1 ? argv[1] : "/";
    struct worker *w = calloc((size_t)count, sizeof(*w));
    for (int i = 0; i < count; i++) {
        snprintf(w[i].path, sizeof(w[i].path), "%s/fifo%d", dir, i);
        unlink(w[i].path);
        if (mkfifo(w[i].path, 0600))
            return 2;
        w[i].stack = mmap(0, STACK, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(w[i].stack, PATTERN, STACK);
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstack(&attr, w[i].stack, STACK);
        if (pthread_create(&w[i].thread, &attr, blocked_open, &w[i]))
            return 3;
    }
    usleep(500000); /* All in the open (or failed already). */
    for (int i = 0; i < count; i++) {
        int fd = open(w[i].path, O_WRONLY | O_NONBLOCK);
        if (fd >= 0)
            close(fd);
    }
    int opened = 0;
    size_t deepest = 0;
    char errors[256] = "";
    for (int i = 0; i < count; i++) {
        pthread_join(w[i].thread, 0);
        if (!w[i].result) {
            opened++;
        } else if (!strstr(errors, strerror(w[i].result))) {
            strncat(errors, strerror(w[i].result), sizeof(errors) - strlen(errors) - 3);
            strcat(errors, "; ");
        }
        size_t k = 0;
        while (k < STACK && w[i].stack[k] == PATTERN)
            k++;
        if (STACK - k > deepest)
            deepest = STACK - k;
        unlink(w[i].path);
    }
    printf("opened %d/%d\nerrors %s\ndeepest %zu\n", opened, count, errors[0] ? errors : "-", deepest);
    return 0;
}
