#include <stddef.h>
#include <stdint.h>

#include "hook_runtime.h"
#include "stub.h"
#include "syscall_nums.h"

/*
 * 运行期补钩：在动态装载新段并设置可执行权限后，再扫描其中的 SVC 指令，
 * 替换成跳转到 payload 的桩，避免后续加载的共享库逃逸。
 *
 * 依赖 minimal syscalls/raw_syscall，不依赖宿主 libc。
 */

#define ARM64_SVC0         0xd4000001u
#define STUB_PAGE_SIZE     4096
#define STUB_DIST_LIMIT    (100 * 1024 * 1024)

#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#ifndef PROT_BTI
#define PROT_BTI    0x10
#endif

#define MAP_PRIVATE 0x02
#define MAP_ANON    0x20
#define MAP_FIXED   0x10

extern long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

static void *stub_pool_base;
static size_t stub_pool_offset;

static void sys_flush_cache(void *addr, size_t len)
{
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + len;
    uintptr_t p;
    for (p = start; p < end; p += 4) {
        __asm__ volatile ("dc cvau, %0" : : "r"(p) : "memory");
    }
    __asm__ volatile ("dsb ish");
    for (p = start; p < end; p += 4) {
        __asm__ volatile ("ic ivau, %0" : : "r"(p) : "memory");
    }
    __asm__ volatile ("dsb ish");
    __asm__ volatile ("isb");
}

static uint32_t generate_branch_insn(uintptr_t src, uintptr_t dest)
{
    int64_t offset = (int64_t)dest - (int64_t)src;
    if (offset < -134217728 || offset > 134217727)
        return 0;
    if (offset & 0x3)
        return 0;
    uint32_t imm26 = (uint32_t)((offset >> 2) & 0x03ffffff);
    return 0x14000000 | imm26;
}

static int do_mprotect(void *addr, size_t len, int prot)
{
    long r = raw_syscall(SYS_mprotect, (long)addr, (long)len, prot, 0, 0, 0);
    return (int)r;
}

static void *do_mmap(void *addr, size_t len, int prot, int flags, int fd, long off)
{
    long r = raw_syscall(SYS_mmap, (long)addr, (long)len, prot, flags, fd, off);
    if (r < 0)
        return (void *)-1;
    return (void *)r;
}

static int patch_instruction(uintptr_t addr, uint32_t instruction)
{
    uintptr_t page = addr & ~(uintptr_t)(STUB_PAGE_SIZE - 1);
    if (do_mprotect((void *)page, STUB_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
        return -1;
    *(uint32_t *)addr = instruction;
    sys_flush_cache((void *)addr, 4);
    do_mprotect((void *)page, STUB_PAGE_SIZE, PROT_READ | PROT_EXEC);
    return 0;
}

static void *alloc_stub_slot(uintptr_t hint_addr)
{
    int need_new = 0;
    if (!stub_pool_base) {
        need_new = 1;
    } else if (stub_pool_offset + STUB_SIZE > STUB_PAGE_SIZE) {
        need_new = 1;
    } else {
        int64_t dist = (int64_t)stub_pool_base - (int64_t)hint_addr;
        if (dist < 0) dist = -dist;
        if (dist > STUB_DIST_LIMIT)
            need_new = 1;
    }

    if (need_new) {
        uintptr_t hint = (hint_addr + STUB_PAGE_SIZE) & ~(uintptr_t)(STUB_PAGE_SIZE - 1);
        void *page = do_mmap((void *)hint, STUB_PAGE_SIZE,
                             PROT_READ | PROT_WRITE | PROT_EXEC | PROT_BTI,
                             MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (page == (void *)-1) {
            page = do_mmap(NULL, STUB_PAGE_SIZE,
                           PROT_READ | PROT_WRITE | PROT_EXEC | PROT_BTI,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
        }
        if (page == (void *)-1) {
            page = do_mmap(NULL, STUB_PAGE_SIZE,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
        }
        if (page == (void *)-1)
            return NULL;
        stub_pool_base = page;
        stub_pool_offset = 0;
    }

    void *slot = (void *)((uintptr_t)stub_pool_base + stub_pool_offset);
    stub_pool_offset += STUB_SIZE;
    return slot;
}

static uintptr_t create_stub(uintptr_t near_addr, uintptr_t payload_addr, uintptr_t return_addr)
{
    void *slot = alloc_stub_slot(near_addr);
    if (!slot)
        return 0;
    stub_emit(slot, payload_addr, return_addr);
    sys_flush_cache(slot, STUB_SIZE);
    return (uintptr_t)slot;
}

int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size)
{
    (void)payload_size;
    if (!target_base || !payload_entry || target_size < 4)
        return 0;

    uint32_t *code = (uint32_t *)target_base;
    size_t count = target_size / 4;
    int hooked = 0;

    for (size_t i = 0; i < count; i++) {
        if (code[i] != ARM64_SVC0)
            continue;

        uintptr_t hook_addr = (uintptr_t)&code[i];
        uintptr_t return_addr = hook_addr + 4;

        uintptr_t stub_addr = create_stub(hook_addr, (uintptr_t)payload_entry, return_addr);
        if (!stub_addr)
            continue;

        uint32_t br = generate_branch_insn(hook_addr, stub_addr);
        if (!br)
            continue;

        if (patch_instruction(hook_addr, br) == 0)
            hooked++;
    }

    return hooked;
}
