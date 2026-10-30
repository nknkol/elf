#include <stddef.h>
#include <stdint.h>

#include "hook_runtime.h"
#include "config.h"
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
long island_pread(int fd, void *buf, size_t len, long offset)
{
    return raw_syscall(__NR_pread64, fd, (long)buf, (long)len, offset, 0, 0);
}

/* Memory the guest's own mm calls must not unmap, remap or reprotect: the
 * payload image and the loader image with its islands (fixed before the
 * guest runs: the config the loader wrote), and the islands made at run
 * time (appended lock-free; fork copies them). Nothing is lazily copied,
 * so no check can see a half-filled table. */
#define PROTECTED_MAX 4096
static uintptr_t protected_lo[PROTECTED_MAX], protected_hi[PROTECTED_MAX];
static unsigned protected_count;
extern char __ehdr_start[], _end[];

/* Nonzero when the table is full: callers must not rely on protection. */
static int protected_add(uintptr_t lo, uintptr_t hi)
{
    unsigned n = __atomic_load_n(&protected_count, __ATOMIC_ACQUIRE);
    do {
        if (n >= PROTECTED_MAX) return -1;
    } while (!__atomic_compare_exchange_n(&protected_count, &n, n + 1, 0,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    protected_lo[n] = lo;
    __atomic_store_n(&protected_hi[n], hi, __ATOMIC_RELEASE);
    return 0;
}

int island_note(uintptr_t base, size_t len)
{
    return protected_add(base, base + len);
}

int hook_protected_overlap(uintptr_t addr, size_t len)
{
    if (!len) return 0;
    uintptr_t end = addr + len < addr ? (uintptr_t)-1 : addr + len;
    if (addr < (((uintptr_t)_end + 4095) & ~(uintptr_t)4095) && end > (uintptr_t)__ehdr_start)
        return 1;
    for (uint32_t i = 0; i < g_payload_config.protected_count && i < 64; i++)
        if (addr < g_payload_config.protected_ranges[i][1] &&
            end > g_payload_config.protected_ranges[i][0])
            return 1;
    unsigned n = __atomic_load_n(&protected_count, __ATOMIC_ACQUIRE);
    if (n > PROTECTED_MAX) n = PROTECTED_MAX;
    for (unsigned i = 0; i < n; i++) {
        uintptr_t hi = __atomic_load_n(&protected_hi[i], __ATOMIC_ACQUIRE);
        if (hi && addr < hi && end > protected_lo[i]) return 1;
    }
    return 0;
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

long install_hook_file(void *target_base, size_t target_size, void *payload_entry, int prot,
                       int fd, unsigned long file_off)
{
    if (!target_base || !payload_entry || target_size < 4)
        return 0;
    struct island_code code[ISLAND_CODE_MAX];
    /* Section headers do not limit control flow: only with the seccomp
     * backstop catching anything skipped may scanning trust them. */
    int ranges = g_payload_config.seccomp_backstop ?
        island_code_ranges(fd, file_off, target_size, code) : 0;
    /* Code that may already run stays executable while patched; fresh code
     * (final prot without exec) is patched through a plain writable view. */
    int writable = (prot & PROT_EXEC) ? PROT_READ | PROT_WRITE | PROT_EXEC : PROT_READ | PROT_WRITE;
    return island_hook_code((uintptr_t)target_base, target_size, (uintptr_t)payload_entry,
                            writable, prot, code, ranges);
}

int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size)
{
    (void)payload_size;
    long rc = install_hook_prot(target_base, target_size, payload_entry, PROT_READ | PROT_EXEC);
    return rc > 0 ? (int)rc : 0;
}
