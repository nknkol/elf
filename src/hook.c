#include "hook.h"
#include "z_syscalls.h"
#include "z_utils.h"

#define ARM64_NOP 0xd503201f
#define PAYLOAD_MAGIC 0x484F4F4B /* "HOOK" */

/* Payload Header Structure */
typedef struct {
    uint32_t branch_instruction; // 0x00
    uint32_t magic;              // 0x04
    uint32_t tail_offset;        // 0x08
    uint32_t version;            // 0x0C
} payload_header_t;

/* Generate ARM64 B (Branch) instruction */
static uint32_t generate_branch_insn(uintptr_t src, uintptr_t dest)
{
    int64_t offset = (int64_t)dest - (int64_t)src;
    if (offset < -134217728 || offset > 134217727) {
        z_printf("[Hook] Error: Offset too large: %ld\n", offset);
        return 0;
    }
    if (offset % 4 != 0) return 0;
    uint32_t imm26 = (offset >> 2) & 0x03ffffff;
    return 0x14000000 | imm26;
}

/* * Manual Cache Flush for AArch64 (replaces __builtin___clear_cache)
 * Essential for self-modifying code in nostdlib environments.
 */
static void sys_flush_cache(void *addr, size_t len) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + len;
    uintptr_t p;

    /* * 1. Clean Data Cache to Point of Unification (PoU)
     * We iterate by 4 bytes to be safe (ignoring cache line size calculation for simplicity).
     * Since we usually patch 4 bytes, this loop runs once or twice.
     */
    for (p = start; p < end; p += 4) {
        __asm__ volatile ("dc cvau, %0" : : "r"(p) : "memory");
    }
    /* Ensure last byte is covered if len is not aligned */
    if (p < end + 4) {
         __asm__ volatile ("dc cvau, %0" : : "r"(end - 1) : "memory");
    }
    
    __asm__ volatile ("dsb ish"); // Data Synchronization Barrier

    /* * 2. Invalidate Instruction Cache to Point of Unification (PoU)
     */
    for (p = start; p < end; p += 4) {
        __asm__ volatile ("ic ivau, %0" : : "r"(p) : "memory");
    }
    if (p < end + 4) {
         __asm__ volatile ("ic ivau, %0" : : "r"(end - 1) : "memory");
    }

    __asm__ volatile ("dsb ish"); // Barrier
    __asm__ volatile ("isb");     // Instruction Synchronization Barrier (Flush pipeline)
}

static int patch_instruction(uintptr_t addr, uint32_t instruction)
{
    uintptr_t page_start = addr & ~(4096 - 1);
    
    /* 1. RW */
    if (z_mprotect((void*)page_start, 4096, PROT_READ | PROT_WRITE) < 0) return -1;
    
    /* 2. Write */
    *(uint32_t*)addr = instruction;
    
    /* 3. Flush Cache (Manual implementation) */
    sys_flush_cache((void*)addr, 4);

    /* 4. RX */
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
    (void)payload_size; 
    uint32_t *code = (uint32_t *)target_base;
    size_t count = target_size / 4;
    
    /* 1. Parse Payload Header */
    payload_header_t *header = (payload_header_t *)payload_entry;
    if (header->magic != PAYLOAD_MAGIC) {
        z_printf("[Hook] Error: Invalid Payload Magic (Expected %x, Got %x)\n", 
                 PAYLOAD_MAGIC, header->magic);
        return 0;
    }
    
    z_printf("[Hook] Payload Header Detected. Tail Offset: 0x%x\n", header->tail_offset);

    /* 2. Calculate absolute address of return trampoline */
    uintptr_t payload_tail_addr = (uintptr_t)payload_entry + header->tail_offset;

    z_printf("[Hook] Scanning for Magic Sequence (4x NOP)...\n");

    for (size_t i = 0; i < count - 4; i++) {
        if (code[i] == ARM64_NOP && code[i+1] == ARM64_NOP && 
            code[i+2] == ARM64_NOP && code[i+3] == ARM64_NOP) 
        {
            uintptr_t hook_addr = (uintptr_t)&code[i];
            z_printf("[Hook] Found candidate at %p\n", (void*)hook_addr);

            /* Target Return Address (hook_addr + 4) */
            uintptr_t return_addr = hook_addr + 4;
            
            /* Step 3: Patch Payload Tail (Jump Back) */
            uint32_t jmp_back = generate_branch_insn(payload_tail_addr, return_addr);
            if (jmp_back == 0) continue;

            z_printf("[Hook] Patching Tail %p -> %p\n", (void*)payload_tail_addr, (void*)return_addr);
            
            /* Patch Tail (It's currently RW from load_raw_payload) */
            *(uint32_t*)payload_tail_addr = jmp_back;
            sys_flush_cache((void*)payload_tail_addr, 4);

            /* Lock Payload to RX */
            // Align length to page size for mprotect
            uintptr_t payload_page = (uintptr_t)payload_entry & ~(4096 - 1);
            size_t aligned_len = ((payload_size + 4095) / 4096) * 4096;
            z_mprotect((void*)payload_page, aligned_len, PROT_READ | PROT_EXEC);

            /* Step 4: Patch Host (Jump to Payload) */
            uint32_t jmp_to_payload = generate_branch_insn(hook_addr, (uintptr_t)payload_entry);
            
            z_printf("[Hook] Patching Host NOP %p -> %p\n", (void*)hook_addr, payload_entry);
            if (patch_instruction(hook_addr, jmp_to_payload) < 0) {
                 z_printf("[Hook] Failed to patch host\n");
                 return 0;
            }

            z_printf("[Hook] Hook installed successfully!\n");
            return 1;
        }
    }
    z_printf("[Hook] Magic Sequence not found.\n");
    return 0;
}