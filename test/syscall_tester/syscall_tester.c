#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <setjmp.h>
#include <fcntl.h>
#include <stdint.h>

/* AArch64 Syscall Definitions (确保覆盖所有嫌疑对象) */
#ifndef __NR_prctl
#define __NR_prctl 167
#endif
#ifndef __NR_membarrier
#define __NR_membarrier 283
#endif
#ifndef __NR_statx
#define __NR_statx 291
#endif
#ifndef __NR_rseq
#define __NR_rseq 293
#endif
#ifndef __NR_clone3
#define __NR_clone3 435
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

/* Test Control Variables */
static sigjmp_buf jump_env;
static const char* current_test_name = "Unknown";

/* Signal Handler: 捕获并跳过崩溃的测试 */
void signal_handler(int sig) {
    printf("\n  [!!!] CRITICAL FAILURE in test '%s'!\n", current_test_name);
    if (sig == SIGSYS) {
        printf("  [!!!] Result: SIGSYS (Signal 31). The kernel BLOCKED this syscall.\n");
    } else if (sig == SIGSEGV) {
        printf("  [!!!] Result: SIGSEGV (Signal 11). Illegal memory access (XOM or W^X violation).\n");
    } else if (sig == SIGILL) {
        printf("  [!!!] Result: SIGILL (Signal 4). Illegal Instruction (CPU blocked execution?).\n");
    } else {
        printf("  [!!!] Result: Signal %d.\n", sig);
    }
    printf("  [!!!] Action: Marking as FAILED and skipping.\n");
    
    // Jump back to main loop
    siglongjmp(jump_env, 1);
}

void register_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGSYS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

void start_test(const char* name) {
    current_test_name = name;
    printf("[TEST] Checking %-30s ... ", name);
    fflush(stdout);
}

void end_test_success() {
    printf("PASS\n");
}

/* ================= 测试用例 ================= */

/* 1. rseq: Glibc 线程初始化核心 */
void test_rseq() {
    start_test("sys_rseq (293)");
    syscall(__NR_rseq, 0, 0, 0, 0);
    end_test_success();
}

/* 2. membarrier: 多线程同步/JIT/GC */
void test_membarrier() {
    start_test("sys_membarrier (283)");
    // MEMBARRIER_CMD_QUERY = 0
    syscall(__NR_membarrier, 0, 0, 0);
    end_test_success();
}

/* 3. prctl: VMA 命名 (Glibc 常用) */
void test_prctl_vma() {
    start_test("prctl(PR_SET_VMA, 0x53564d41)");
    // 0x53564d41 是 "SVMA" 的 ASCII，Glibc 用它来标记匿名内存
    syscall(__NR_prctl, 0x53564d41, 0, 0, 0, 0);
    end_test_success();
}

/* 4. faccessat2: 新版文件权限检查 */
void test_faccessat2() {
    start_test("sys_faccessat2 (439)");
    syscall(__NR_faccessat2, AT_FDCWD, (long)".", R_OK, 0);
    end_test_success();
}

/* 5. clone3: 新版线程/进程创建 */
void test_clone3() {
    start_test("sys_clone3 (435)");
    // 传入 NULL 应该返回 -EINVAL 或 -ENOSYS，但不应该崩
    syscall(__NR_clone3, 0, 0);
    end_test_success();
}

/* 6. statx: 新版文件状态 */
void test_statx() {
    start_test("sys_statx (291)");
    syscall(__NR_statx, AT_FDCWD, (long)".", 0, 0, 0);
    end_test_success();
}

/* 7. XOM Check: 检测内核是否强制 Execute-Only Memory */
/* 这是导致 Signal 11 的最大嫌疑 */
void test_xom() {
    start_test("XOM Policy (mprotect EXEC)");
    
    size_t size = 4096;
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) { printf("mmap failed! "); return; }
    
    // 写入一个标记
    *(volatile int*)p = 0x12345678;

    // 关键步骤：请求只执行 (PROT_EXEC)，不带 PROT_READ
    if (mprotect(p, size, PROT_EXEC) < 0) {
        printf("mprotect failed! ");
        return;
    }

    // 关键测试：尝试读取它。
    // 如果内核是强安全的，这里会触发 SIGSEGV。
    // 如果内核是宽容的 (隐含 READ)，这里会成功。
    volatile int val = *(volatile int*)p;
    (void)val;

    end_test_success();
    munmap(p, size);
}

/* 8. W^X Check: 检测内核是否允许同时可写可执行 */
/* 如果你的 Hook 机制尝试申请 RWX 内存，在这里可能会崩 */
void test_wx() {
    start_test("W^X Policy (mmap RWX)");
    
    size_t size = 4096;
    // 尝试直接申请 RWX
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (p == MAP_FAILED) {
        // mmap 直接失败是预期内的安全行为，不算崩溃
        printf("PASS (mmap RWX rejected, safe)\n");
        return;
    }

    // 如果申请成功了，尝试写
    *(volatile int*)p = 0x90909090; // NOPs

    // 尝试执行 (这就很难在纯C里测了，不跳过去也没事，没崩就行)
    end_test_success(); 
    // 注意：如果内核发现你申请了 RWX，可能会杀掉你，这也是一种测试
    munmap(p, size);
}

int main() {
    printf("=== HarmonyOS/Android Kernel Suicide Tester ===\n");
    printf("Running checks for incompatible syscalls and memory policies...\n\n");

    register_handlers();

    // 设置跳转点，如果测试崩了会回到这里继续下一个
    if (sigsetjmp(jump_env, 1) != 0) {
        // 从信号处理程序跳回来的
    }

    // 简单的状态机来决定跑哪个测试
    static int step = 0;
    switch(step) {
        case 0: step++; test_rseq();
        case 1: step++; test_membarrier();
        case 2: step++; test_prctl_vma();
        case 3: step++; test_faccessat2();
        case 4: step++; test_clone3();
        case 5: step++; test_statx();
        case 6: step++; test_xom();  // <--- 重点关注这个
        case 7: step++; test_wx();
    }

    printf("\n=== Test Suite Finished ===\n");
    printf("Analysis Guide:\n");
    printf("1. SIGSYS:  Add interception in loader -> return -ENOSYS.\n");
    printf("2. SIGSEGV in XOM: Loader MUST force 'PROT_READ' when app requests 'PROT_EXEC'.\n");
    printf("3. SIGSEGV in W^X: Loader hook mechanism needs valid mprotect sequences (RW->RX).\n");

    return 0;
}