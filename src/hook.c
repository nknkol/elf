#include "hook.h"
#include "z_syscalls.h"
#include "z_utils.h"

#define ARM64_NOP   0xd503201f
#define ARM64_SVC0  0xd4000001  /* svc #0 */
#define PAYLOAD_MAGIC 0x484F4F4B

/* Payload Header Structure */
typedef struct {
    uint32_t branch_instruction; // 0x00
    uint32_t magic;              // 0x04
    uint32_t tail_offset;        // 0x08
    uint32_t version;            // 0x0C
} payload_header_t;

/* Generate ARM64 B (Branch) instruction (Range: +/- 128MB) */
static uint32_t generate_branch_insn(uintptr_t src, uintptr_t dest)
{
    int64_t offset = (int64_t)dest - (int64_t)src;
    if (offset < -134217728 || offset > 134217727) {
        return 0; // Out of range
    }
    if (offset % 4 != 0) return 0;
    uint32_t imm26 = (offset >> 2) & 0x03ffffff;
    return 0x14000000 | imm26;
}

/* Manual Cache Flush */
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

/*
 * Helper: Write Absolute Jump (LDR + BR)
 * Requires 16 bytes of space.
 * Code:
 * ldr x16, .+8    (0x58000050)
 * br x16          (0xd61f0200)
 * [64-bit Addr]
 */
static void write_absolute_jump(void *location, uintptr_t target) {
    uint32_t *code = (uint32_t *)location;
    code[0] = 0x58000050; // ldr x16, PC+8
    code[1] = 0xd61f0200; // br x16
    *(uintptr_t *)(&code[2]) = target; // 64-bit Address
    sys_flush_cache(location, 16);
}

/*
 * Create a Stub Island near the target address.
 * Used when the Payload is too far for a direct branch.
 */
static uintptr_t create_stub_island(uintptr_t near_addr, uintptr_t jump_dest) {
    size_t page_size = 4096;
    // Try to find a free page after the target segment (hint)
    uintptr_t hint_addr = (near_addr + page_size) & ~(page_size - 1);
    
    // Allocate RXW memory
    void *island = z_mmap((void*)hint_addr, page_size, 
                          PROT_READ | PROT_WRITE | PROT_EXEC, 
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                          
    if (island == (void*)-1) {
        z_printf("[Hook] Error: Failed to allocate Island.\n");
        return 0;
    }

    z_printf("[Hook] Allocated Stub Island at %p (near %p)\n", island, (void*)near_addr);

    // Write absolute jump to Payload in the island
    write_absolute_jump(island, jump_dest);
    
    return (uintptr_t)island;
}

static int patch_instruction(uintptr_t addr, uint32_t instruction)
{
    uintptr_t page_start = addr & ~(4096 - 1);
    if (z_mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE) < 0) return -1;
    *(uint32_t*)addr = instruction;
    sys_flush_cache((void*)addr, 4);
    if (z_mprotect((void*)page_start, 4096, PROT_READ | PROT_EXEC) < 0) return -1;
    return 0;
}

void *load_raw_payload(const char *path, size_t *size_out)
{
    int fd = z_open(path, O_RDONLY);
    if (fd < 0) return NULL;
    off_t sz = z_lseek(fd, 0, SEEK_END);
    z_lseek(fd, 0, SEEK_SET);
    void *base = z_mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == (void *)-1) { z_close(fd); return NULL; }
    z_read(fd, base, sz);
    z_close(fd);
    if (size_out) *size_out = sz;
    return base;
}

int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size)
{
    /* [修复] 添加静态标志位，防止多次 Hook 导致的权限崩溃 */
    static int is_installed = 0;
    if (is_installed) {
        return 0;
    }

    uint32_t *code = (uint32_t *)target_base;
    size_t count = target_size / 4;
    
    payload_header_t *header = (payload_header_t *)payload_entry;
    if (header->magic != PAYLOAD_MAGIC) {
        z_printf("[Hook] Error: Invalid Payload Magic (Expected %x, Got %x)\n", 
                 PAYLOAD_MAGIC, header->magic);
        return 0;
    }
    
    uintptr_t payload_tail_addr = (uintptr_t)payload_entry + header->tail_offset;

    z_printf("[Hook] Scanning for SVC #0 (0x%x)...\n", ARM64_SVC0);

    for (size_t i = 0; i < count; i++) {
        if (code[i] == ARM64_SVC0) 
        {
            uintptr_t hook_addr = (uintptr_t)&code[i];
            z_printf("[Hook] Found SVC #0 at %p\n", (void*)hook_addr);

            /* Step 1: Patch Payload Return */
            uintptr_t return_addr = hook_addr + 4;
            
            uint32_t jmp_back = generate_branch_insn(payload_tail_addr, return_addr);
            
            if (jmp_back != 0) {
                z_printf("[Hook] Patching Return (Direct Branch)\n");
                /* 注意：此时 Payload 还是 RW 的，可以写入 */
                *(uint32_t*)payload_tail_addr = jmp_back;
                sys_flush_cache((void*)payload_tail_addr, 4);
            } else {
                z_printf("[Hook] Patching Return (Absolute Jump)\n");
                write_absolute_jump((void*)payload_tail_addr, return_addr);
            }

            /* 锁定 Payload 为 RX (导致后续写入崩溃的根源，但对于安全运行是必须的) */
            uintptr_t payload_page = (uintptr_t)payload_entry & ~(4096 - 1);
            size_t aligned_len = ((payload_size + 4095) / 4096) * 4096;
            z_mprotect((void*)payload_page, aligned_len, PROT_READ | PROT_EXEC);

            /* Step 2: Patch Host */
            uintptr_t target_dest = (uintptr_t)payload_entry;
            uint32_t jmp_to_payload = generate_branch_insn(hook_addr, target_dest);
            
            if (jmp_to_payload == 0) {
                z_printf("[Hook] Payload too far. Creating Stub Island...\n");
                uintptr_t island_addr = create_stub_island(hook_addr, target_dest);
                if (!island_addr) return 0;
                
                jmp_to_payload = generate_branch_insn(hook_addr, island_addr);
                if (jmp_to_payload == 0) {
                     z_printf("[Hook] Fatal: Island is also too far!\n");
                     return 0;
                }
                z_printf("[Hook] Patching Host: %p -> Island: %p -> Payload\n", (void*)hook_addr, (void*)island_addr);
            } else {
                z_printf("[Hook] Patching Host (Direct): %p -> %p\n", (void*)hook_addr, (void*)target_dest);
            }

            if (patch_instruction(hook_addr, jmp_to_payload) < 0) {
                 z_printf("[Hook] Failed to patch host\n");
                 return 0;
            }

            z_printf("[Hook] Hook installed successfully!\n");
            
            /* [修复] 标记已安装，阻止后续调用 */
            is_installed = 1;
            return 1;
        }
    }
    // z_printf("[Hook] SVC #0 not found in this segment.\n"); 
    // 这一行可以注释掉，避免每个 segment 都报错
    return 0;
}