#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

// 子进程执行的函数
static int child_fn(void *arg) {
    printf("[Child] Inside new User Namespace!\n");
    // 在新的 User Namespace 里，我们通常会变成 nobody 或者通过映射变成 root
    // 这里简单打印一下当前的 UID/GID
    printf("[Child] My UID: %d, GID: %d\n", getuid(), getgid());
    return 0;
}

// 栈大小
#define STACK_SIZE (1024 * 1024)

int main() {
    // 为子进程分配栈空间
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        exit(1);
    }

    printf("[Parent] Trying to clone with CLONE_NEWUSER...\n");

    // 这里的关键是 CLONE_NEWUSER 标志
    // 如果内核支持 UserNS，这行调用会成功
    // 栈向下增长，所以指针指向 stack + STACK_SIZE
    pid_t pid = clone(child_fn, stack + STACK_SIZE, CLONE_NEWUSER | SIGCHLD, NULL);

    if (pid == -1) {
        perror("[Parent] clone failed (UserNS implies kernel config issue?)");
        exit(1);
    }

    // 等待子进程结束
    waitpid(pid, NULL, 0);
    printf("[Parent] Child process finished.\n");

    return 0;
}