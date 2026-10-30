#include <stddef.h>
#include <stdint.h>

#include "hook_runtime.h"
#include "stub.h"
#include "stub_island.h"
#include "syscall_nums.h"

/*
 * 运行期补钩：在动态装载新段并设置可执行权限后，再扫描其中的 SVC 指令，
 * 替换成跳转到 payload 的桩，避免后续加载的共享库逃逸。桩的放置见
 * stub_island.h：两侧桩岛覆盖至 256 MiB 的段，无法覆盖时整段失败。
 *
 * 依赖 minimal syscalls/raw_syscall，不依赖宿主 libc。
 */


#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#ifndef PROT_BTI
#define PROT_BTI    0x10
#endif

extern long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

long island_mmap(uintptr_t addr, size_t len, int prot, int flags)
{
    return raw_syscall(SYS_mmap, (long)addr, (long)len, prot, flags, -1, 0);
}
long island_munmap(uintptr_t addr, size_t len)
{
    return raw_syscall(__NR_munmap, (long)addr, (long)len, 0, 0, 0, 0);
}
long island_mprotect(uintptr_t addr, size_t len, int prot)
{
    return raw_syscall(SYS_mprotect, (long)addr, (long)len, prot, 0, 0, 0);
}

long install_hook_prot(void *target_base, size_t target_size, void *payload_entry, int prot)
{
    if (!target_base || !payload_entry || target_size < 4)
        return 0;
    /* Other threads may already run this code: keep it executable while
     * patching (each branch is a single aligned store). */
    return island_hook_range((uintptr_t)target_base, target_size, (uintptr_t)payload_entry,
                             PROT_READ | PROT_WRITE | PROT_EXEC, prot);
}

int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size)
{
    (void)payload_size;
    long rc = install_hook_prot(target_base, target_size, payload_entry, PROT_READ | PROT_EXEC);
    return rc > 0 ? (int)rc : 0;
}
