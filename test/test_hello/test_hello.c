#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <fcntl.h>

#define __NR_getcwd 17
#define __NR_faccessat 48
#define __NR_openat 56
#define __NR_newfstatat 79
#define __NR_write 64
#define __NR_close 57

/* 辅助函数：内联汇编系统调用 */
long my_syscall1(long n, long a1) {
    long ret;
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    asm volatile("svc #0" : "=r"(ret) : "r"(x8), "r"(x0) : "memory", "cc");
    return ret;
}

long my_syscall2(long n, long a1, long a2) {
    long ret;
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    register long x1 asm("x1") = a2;
    asm volatile("svc #0" : "=r"(ret) : "r"(x8), "r"(x0), "r"(x1) : "memory", "cc");
    return ret;
}

long my_syscall3(long n, long a1, long a2, long a3) {
    long ret;
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    register long x1 asm("x1") = a2;
    register long x2 asm("x2") = a3;
    asm volatile("svc #0" : "=r"(ret) : "r"(x8), "r"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    return ret;
}

long my_syscall4(long n, long a1, long a2, long a3, long a4) {
    long ret;
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a1;
    register long x1 asm("x1") = a2;
    register long x2 asm("x2") = a3;
    register long x3 asm("x3") = a4;
    asm volatile("svc #0" : "=r"(ret) : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return ret;
}

/* * [DEBUG] 原始日志宏 
 * 直接陷入内核，绕过 libc 缓冲，确保崩溃前一定能输出
 */
#define RAW_LOG(msg) my_syscall3(__NR_write, 1, (long)(msg), sizeof(msg)-1)

int main() {
    char buf[128];
    long ret;
    
    /* 这里的 printf 可能会被缓冲，所以我们加上 RAW_LOG */
    printf("============================================\n");
    printf("[Target] PID: %d. Started Multi-Syscall Test.\n", getpid());
    
    RAW_LOG("[Target] >>> Ready to call getcwd...\n");

    memset(buf, 0, sizeof(buf));
    
    /* === 关键测试点 === */
    ret = my_syscall2(__NR_getcwd, (long)buf, sizeof(buf));
    /* ================= */

    /* 如果能看到这句话，说明 Hook 成功返回了 */
    RAW_LOG("[Target] <<< getcwd returned!\n");

    if (ret > 0) printf("  -> CWD: %s\n", buf);
    else printf("  -> getcwd failed: %ld\n", ret);

    /* 2. 测试 FACCESSAT */
    printf("[Target] Testing faccessat...\n");
    ret = my_syscall3(__NR_faccessat, -100, (long)"payload.bin", 0);
    printf("  -> faccessat returned: %ld\n", ret);

    /* 其他测试略... (保持原样即可) */
    
    printf("============================================\n");
    return 0;
}