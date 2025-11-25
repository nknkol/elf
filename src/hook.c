#include "hook.h"
#include "z_syscalls.h"
#include "z_utils.h"

#define ARM64_NOP   0xd503201f
#define ARM64_SVC0  0xd4000001
#define PAYLOAD_MAGIC 0x484F4F4B
#define STUB_SIZE       64
#define STUB_PAGE_SIZE  4096
#define STUB_DIST_LIMIT (100 * 1024 * 1024) /* keep within 100MB for branch range */

static int g_hook_min = 0;
static int g_hook_max = 0x7fffffff;

void set_hook_range(int min, int max) {
    g_hook_min = min;
    g_hook_max = max;
    z_printf("[Hook] Config: Range [%d - %d]\n", g_hook_min, g_hook_max);
}

/* Stub Pool State */
static void *stub_pool_base = NULL;
static size_t stub_pool_offset = 0;

/* Helper Functions */

static uint32_t generate_branch_insn(uintptr_t src, uintptr_t dest)
{
    int64_t offset = (int64_t)dest - (int64_t)src;

    if (offset < -134217728 || offset > 134217727) {
        z_printf("[Hook Error] Branch out of range! Dist: %ld\n", offset);
        return 0;
    }
    if (offset % 4 != 0) {
        z_printf("[Hook Error] Branch target not aligned!\n");
        return 0;
    }
    uint32_t imm26 = (offset >> 2) & 0x03ffffff;
    return 0x14000000 | imm26;
}

static void sys_flush_cache(void *addr, size_t len) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + len;
    uintptr_t p;
    for (p = start; p < end; p += 4) {
        __asm__ volatile ("dc cvau, %0" : : "r"(p) : "memory");
    }
    if (p < end + 4) __asm__ volatile ("dc cvau, %0" : : "r"(end - 1) : "memory");
    __asm__ volatile ("dsb ish");
    for (p = start; p < end; p += 4) {
        __asm__ volatile ("ic ivau, %0" : : "r"(p) : "memory");
    }
    if (p < end + 4) __asm__ volatile ("ic ivau, %0" : : "r"(end - 1) : "memory");
    __asm__ volatile ("dsb ish");
    __asm__ volatile ("isb");
}

static int patch_instruction(uintptr_t addr, uint32_t instruction)
{
    uintptr_t page_start = addr & ~(4096 - 1);
    if (z_mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE) < 0)
        return -1;
    *(uint32_t*)addr = instruction;
    sys_flush_cache((void*)addr, 4);
    if (z_mprotect((void*)page_start, 4096, PROT_READ | PROT_EXEC) < 0)
        return -1;
    return 0;
}

/* Stub Allocator */
static void *alloc_stub_slot(uintptr_t hint_addr) {
    int need_new = 0;
    
    if (stub_pool_base == NULL) {
        need_new = 1;
    } else if (stub_pool_offset + STUB_SIZE > STUB_PAGE_SIZE) {
        z_printf("[Hook] Stub Page Full. Allocating new.\n");
        need_new = 1;
    } else {
        int64_t dist = (int64_t)stub_pool_base - (int64_t)hint_addr;
        if (dist < 0) dist = -dist;
        if (dist > STUB_DIST_LIMIT) {
            z_printf("[Hook] Stub Page too far (%ld bytes). Allocating new.\n", dist);
            need_new = 1;
        }
    }

    if (need_new) {
        // Try to allocate "near" the hint address
        uintptr_t new_hint = (hint_addr + 4096) & ~(4096 - 1);
        void *new_page = z_mmap((void*)new_hint, STUB_PAGE_SIZE, 
                                PROT_READ | PROT_WRITE | PROT_EXEC, 
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        
        if (new_page == (void*)-1) {
            // Fallback: Let kernel decide, hope it's close enough
            new_page = z_mmap(NULL, STUB_PAGE_SIZE, 
                                PROT_READ | PROT_WRITE | PROT_EXEC, 
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }

        if (new_page == (void*)-1) {
            z_printf("[Hook] Fatal: z_mmap failed for stub page!\n");
            return NULL;
        }
        stub_pool_base = new_page;
        stub_pool_offset = 0;
        
        int64_t dist = (int64_t)stub_pool_base - (int64_t)hint_addr;
        z_printf("[Hook] New Stub Page: %p (Dist from target: %ld bytes)\n", stub_pool_base, dist);
    }

    void *slot = (void*)((uintptr_t)stub_pool_base + stub_pool_offset);
    stub_pool_offset += STUB_SIZE;
    return slot;
}

/* Stub Generation */
static uintptr_t create_stub(uintptr_t near_addr, uintptr_t payload_addr, uintptr_t return_addr) {
    void *island = alloc_stub_slot(near_addr);
    if (!island) return 0;

    uint32_t *code = (uint32_t *)island;
    /* Data is now at offset 0x30 (48) */
    uint64_t *data = (uint64_t *)((uintptr_t)island + 0x30); 

    /* Code Generation */
    // 1. adr x16, 0x30 (Offset 48)
    //    Op: 10000000 | (0x180) | 10000 -> 10000190
    code[0] = 0x10000190; 

    // 2. str x30, [x16, #16] (Data[2])
    code[1] = 0xf9000A1e;

    // 3. ldr x17, [x16, #0] (Data[0] - Payload)
    code[2] = 0xf9400211;

    // 4. blr x17 (Call Payload)
    code[3] = 0xd63f0220;

    // 5. adr x16, 0x20 
    //    [CRITICAL FIX] Reload x16! 
    //    Current PC is at offset 0x10. Data is at 0x30. Delta = 0x20.
    //    Op: 10000000 | (0x100) | 10000 -> 10000110
    code[4] = 0x10000110;

    // 6. ldr x30, [x16, #16] (Restore LR)
    code[5] = 0xf9400A1e;

    // 7. ldr x17, [x16, #8] (Data[1] - Return)
    code[6] = 0xf9400611;

    // 8. br x17 (Return to Host)
    code[7] = 0xd61f0220;

    // Padding (NOPs)
    code[8]  = 0xd503201f;
    code[9]  = 0xd503201f;
    code[10] = 0xd503201f;
    code[11] = 0xd503201f;

    /* Data Initialization */
    data[0] = (uint64_t)payload_addr;
    data[1] = (uint64_t)return_addr;
    data[2] = 0; 

    sys_flush_cache(island, STUB_SIZE);
    
    // z_printf("[Hook Debug] Stub created at %p -> Payload %p\n", island, (void*)payload_addr);
    return (uintptr_t)island;
}

void *load_raw_payload(const char *path, size_t *size_out) {
    // Legacy function, using ELF loader now ideally.
    (void)path; (void)size_out;
    return NULL;
}

/* Hook Installation */
int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size)
{
    (void)payload_size;
    if (!payload_entry || !target_base || target_size == 0)
        return 0;

    uint32_t *code = (uint32_t *)target_base;
    size_t count = target_size / 4;
    int hook_count = 0;
    static int scan_index = -1; 

    // payload_header_t *header = (payload_header_t *)payload_entry;
    // Magic check skipped for ELF payload as entry points to code directly

    z_printf("[Hook] Scanning %p - %p (%ld bytes)\n", 
             target_base, (void*)((uintptr_t)target_base + target_size), target_size);

    for (size_t i = 0; i < count; i++) {
        if (code[i] == ARM64_SVC0) 
        {
            scan_index++; 
            if (scan_index < g_hook_min || scan_index > g_hook_max) continue;

            uintptr_t hook_addr = (uintptr_t)&code[i];
            uintptr_t return_addr = hook_addr + 4;

            /* 1. Create Stub */
            uintptr_t stub_addr = create_stub(hook_addr, (uintptr_t)payload_entry, return_addr);
            if (!stub_addr) {
                z_printf("[Hook Error] Alloc stub failed at %p\n", (void*)hook_addr);
                continue;
            }

            /* 2. Calculate Jump */
            uint32_t jmp_to_stub = generate_branch_insn(hook_addr, stub_addr);
            if (jmp_to_stub == 0) {
                 z_printf("[Hook Error] Stub too far from %p to %p. Skipping.\n", (void*)hook_addr, (void*)stub_addr);
                 continue;
            }

            /* 3. Patch */
            if (patch_instruction(hook_addr, jmp_to_stub) < 0) {
                 z_printf("[Hook Error] Failed to patch instruction at %p\n", (void*)hook_addr);
            } else {
                 hook_count++;
                 z_printf("[Hook] Hook #%d: %p -> Stub %p (Dist: %ld)\n", 
                          scan_index, (void*)hook_addr, (void*)stub_addr, (int64_t)(stub_addr - hook_addr));
            }
        }
    }

    z_printf("[Hook] Installed: %d hooks\n", hook_count);
    return hook_count > 0;
}
