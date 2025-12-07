#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/prctl.h>

// 定义那个神秘的 JIT 开关
#define PR_JIT_WORKAROUND 0x6a6974

void test_mmap(const char *desc, int fd, int prot, int flags) {
    printf("[TEST] %-30s: ", desc);
    
    // 如果是匿名映射，fd 设为 -1
    int map_fd = (flags & MAP_ANONYMOUS) ? -1 : fd;
    
    void *ptr = mmap(NULL, 4096, prot, flags, map_fd, 0);
    
    if (ptr == MAP_FAILED) {
        printf("FAILED (errno=%d: %s)\n", errno, strerror(errno));
    } else {
        printf("SUCCESS -> %p\n", ptr);
        munmap(ptr, 4096);
    }
}

void test_mprotect_upgrade(const char *path) {
    printf("\n[TEST] Trying mmap(RW) -> mprotect(RX) sequence:\n");
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("  Open failed: %s\n", strerror(errno));
        return;
    }

    // 1. 先只申请读写 (RW)
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        printf("  Step 1: mmap(RW) FAILED (%s). Aborting.\n", strerror(errno));
        close(fd);
        return;
    }
    printf("  Step 1: mmap(RW) SUCCESS -> %p\n", ptr);

    // 2. 尝试升级为可执行 (RX)
    if (mprotect(ptr, 4096, PROT_READ | PROT_EXEC) == 0) {
        printf("  Step 2: mprotect(RX) SUCCESS! (File-backed executable works!)\n");
    } else {
        printf("  Step 2: mprotect(RX) FAILED (errno=%d: %s)\n", errno, strerror(errno));
        printf("          -> Conclusion: Kernel forbids executable permission on this file.\n");
    }

    // 3. 尝试带 JIT 令牌升级
    printf("  Step 3: Trying with JIT token (prctl 0x6a6974)...\n");
    prctl(PR_JIT_WORKAROUND, 0, 0, 0, 0);
    if (mprotect(ptr, 4096, PROT_READ | PROT_EXEC) == 0) {
        printf("          mprotect(RX) + JIT Token SUCCESS!\n");
    } else {
        printf("          mprotect(RX) + JIT Token FAILED (errno=%d: %s)\n", errno, strerror(errno));
    }
    prctl(PR_JIT_WORKAROUND, 0, 1, 0, 0);

    munmap(ptr, 4096);
    close(fd);
}

int main(int argc, char *argv[]) {
    const char *filepath = "test_file.bin";
    if (argc > 1) {
        filepath = argv[1];
    }

    printf("=== Memory Mapping Test Tool ===\n");
    printf("Target File: %s\n\n", filepath);

    // 准备一个测试文件
    int fd = open(filepath, O_RDWR | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        // 如果无法写入，尝试只读打开（针对现有文件）
        fd = open(filepath, O_RDONLY);
        if (fd < 0) {
            perror("Error opening test file");
            return 1;
        }
    } else {
        write(fd, "TESTCODE", 8);
        fsync(fd);
    }

    // --- 对照组：匿名内存 (Loader 的方式) ---
    test_mmap("Anon mmap (RW)", -1, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS);
    test_mmap("Anon mmap (RX)", -1, PROT_READ | PROT_EXEC,  MAP_PRIVATE | MAP_ANONYMOUS);

    // --- 实验组：文件映射 (Linker 的方式) ---
    // 1. 测试单纯的文件映射 (不带执行权限)
    test_mmap("File mmap (RW) [No Exec]", fd, PROT_READ | PROT_WRITE, MAP_PRIVATE);
    
    // 2. 测试带执行权限的文件映射
    test_mmap("File mmap (RX) [Exec]",    fd, PROT_READ | PROT_EXEC,  MAP_PRIVATE);

    // 3. 测试先映射再修改权限
    close(fd); // test_mprotect_upgrade 内部会重新打开
    test_mprotect_upgrade(filepath);

    return 0;
}