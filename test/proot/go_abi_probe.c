/* What Go's runtime counts on from the kernel (test_go_abi.py), done by
 * hand: raw svc instructions in this program's text, which the loader
 * routes through its stubs.
 *
 * clone: runtime.clone stores m, g, fn and the magic 1234 just below the
 * child's new stack, makes the call, and the child reads them back after a
 * gettid (all signals blocked, so nothing else writes there).
 *
 * x28: Go keeps g in x28 and its signal handler reads it from there. A
 * thread blocks in openat on a FIFO (a call the payload translates, so it
 * blocks inside the payload) with x28 set; a signal's handler records x28. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define G_MAGIC 0x2828282828282828L

static volatile long below[4];
static volatile int child_done;
long seen28 = -1;

static long go_clone(unsigned long flags, char *stack_top)
{
    register long x0 __asm__("x0") = (long)flags;
    register long x1 __asm__("x1") = (long)stack_top;
    register long x2 __asm__("x2") = 0, x3 __asm__("x3") = 0, x4 __asm__("x4") = 0;
    register long x8 __asm__("x8") = SYS_clone;
    __asm__ volatile(
        "mov x10, #11\n str x10, [x1, #-8]\n"     /* m */
        "mov x10, #22\n str x10, [x1, #-16]\n"    /* g */
        "mov x10, #33\n str x10, [x1, #-24]\n"    /* fn */
        "mov x10, #1234\n str x10, [x1, #-32]\n"  /* magic */
        "svc #0\n"
        "cbnz x0, 1f\n"
        "mov x8, #178\n svc #0\n"                  /* gettid, as Go's child */
        "ldr x9, =below\n"
        "ldp x10, x11, [sp, #-32]\n stp x10, x11, [x9]\n"
        "ldp x10, x11, [sp, #-16]\n stp x10, x11, [x9, #16]\n"
        "ldr x9, =child_done\n mov w10, #1\n stlr w10, [x9]\n"
        "mov x0, #0\n mov x8, #93\n svc #0\n"      /* exit (the thread) */
        "1:\n"
        : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8)
        : "x9", "x10", "x11", "memory");
    return x0;
}

__attribute__((naked)) static void record_x28(int sig)
{
    __asm__("adrp x9, seen28\n add x9, x9, :lo12:seen28\n str x28, [x9]\n ret");
}

static void *blocked_open(void *path)
{
    register long x0 __asm__("x0") = AT_FDCWD;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = O_RDONLY;
    register long x3 __asm__("x3") = 0;
    register long x8 __asm__("x8") = SYS_openat;
    register long x28 __asm__("x28") = G_MAGIC;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8), "r"(x28) : "memory");
    if (x0 >= 0)
        close((int)x0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "clone")) {
        char *stack = malloc(65536);
        unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
        long tid = go_clone(flags, stack + 65536);
        for (int i = 0; i < 5000 && !__atomic_load_n(&child_done, __ATOMIC_ACQUIRE); i++)
            usleep(1000);
        printf("clone %d below %ld %ld %ld %ld\n", tid > 0, below[0], below[1], below[2], below[3]);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "x28")) {
        const char *fifo = argv[2];
        if (mkfifo(fifo, 0600) && errno != EEXIST)
            return 2;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = record_x28;
        sigaction(SIGUSR1, &sa, 0); /* no SA_RESTART: the open fails EINTR */
        pthread_t t;
        pthread_create(&t, 0, blocked_open, (void *)fifo);
        usleep(300000);
        pthread_kill(t, SIGUSR1);
        usleep(100000);
        int w = open(fifo, O_WRONLY | O_NONBLOCK); /* in case the open restarted */
        if (w >= 0)
            close(w);
        pthread_join(t, 0);
        printf("x28 %s\n", seen28 == G_MAGIC ? "kept" : "changed");
        return 0;
    }
    return 2;
}
