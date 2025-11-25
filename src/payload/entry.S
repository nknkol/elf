.text
    .align 4
    .global _start

/* Syscall numbers of interest (AArch64) */
.equ    SYS_getcwd,      17
.equ    SYS_faccessat,   48
.equ    SYS_openat,      56
.equ    SYS_close,       57
.equ    SYS_write,       64
.equ    SYS_newfstatat,  79
.equ    SYS_exit,        93
.equ    SYS_exit_group,  94
.equ    SYS_rt_sigreturn,139
.equ    SYS_execve,      221
.equ    SYS_mprotect,    226

/* Stack layout */
.equ    CTX_SIZE,       768     /* GPRs (0..255) + SIMD (256..767) */
.equ    SIMD_AREA,      256

_start:
    b       real_entry

    /* Payload Header */
    .word   0x484F4F4B          /* Magic: "HOOK" */
    .word   0x0                 /* Tail Offset unused */
    .word   0x2                 /* Version: 2 (multi-point / stub-based) */

real_entry:
    /* rt_sigreturn must see the original user stack; bypass */
    cmp     x8, #SYS_rt_sigreturn
    b.eq    fast_path_sigreturn

    /* Quick filter: only instrument syscalls we care about */
    mov     x9, x8
    cmp     x9, #SYS_getcwd
    b.eq    slow_path
    cmp     x9, #SYS_faccessat
    b.eq    slow_path
    cmp     x9, #SYS_openat
    b.eq    slow_path
    cmp     x9, #SYS_close
    b.eq    slow_path
    cmp     x9, #SYS_write
    b.eq    slow_path
    cmp     x9, #SYS_newfstatat
    b.eq    slow_path
    cmp     x9, #SYS_exit
    b.eq    slow_path
    cmp     x9, #SYS_exit_group
    b.eq    slow_path
    cmp     x9, #SYS_execve
    b.eq    slow_path
    cmp     x9, #SYS_mprotect
    b.eq    slow_path
    b       fast_passthrough

slow_path:
    sub     sp, sp, #CTX_SIZE
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    str     x30, [sp, #240]

    /* Save SIMD/FP state (caller-saved + callee-saved) */
    stp     q0, q1,   [sp, #SIMD_AREA + 0]
    stp     q2, q3,   [sp, #SIMD_AREA + 32]
    stp     q4, q5,   [sp, #SIMD_AREA + 64]
    stp     q6, q7,   [sp, #SIMD_AREA + 96]
    stp     q8, q9,   [sp, #SIMD_AREA + 128]
    stp     q10, q11, [sp, #SIMD_AREA + 160]
    stp     q12, q13, [sp, #SIMD_AREA + 192]
    stp     q14, q15, [sp, #SIMD_AREA + 224]
    stp     q16, q17, [sp, #SIMD_AREA + 256]
    stp     q18, q19, [sp, #SIMD_AREA + 288]
    stp     q20, q21, [sp, #SIMD_AREA + 320]
    stp     q22, q23, [sp, #SIMD_AREA + 352]
    stp     q24, q25, [sp, #SIMD_AREA + 384]
    stp     q26, q27, [sp, #SIMD_AREA + 416]
    stp     q28, q29, [sp, #SIMD_AREA + 448]
    stp     q30, q31, [sp, #SIMD_AREA + 480]

    /* Call dispatcher: x0=syscall no, x1=pt_regs */
    mov     x0, x8
    mov     x1, sp
    bl      syscall_dispatcher

    /* Write back return value into saved context */
    str     x0, [sp, #0]

    /* Restore SIMD/FP */
    ldp     q30, q31, [sp, #SIMD_AREA + 480]
    ldp     q28, q29, [sp, #SIMD_AREA + 448]
    ldp     q26, q27, [sp, #SIMD_AREA + 416]
    ldp     q24, q25, [sp, #SIMD_AREA + 384]
    ldp     q22, q23, [sp, #SIMD_AREA + 352]
    ldp     q20, q21, [sp, #SIMD_AREA + 320]
    ldp     q18, q19, [sp, #SIMD_AREA + 288]
    ldp     q16, q17, [sp, #SIMD_AREA + 256]
    ldp     q14, q15, [sp, #SIMD_AREA + 224]
    ldp     q12, q13, [sp, #SIMD_AREA + 192]
    ldp     q10, q11, [sp, #SIMD_AREA + 160]
    ldp     q8, q9,   [sp, #SIMD_AREA + 128]
    ldp     q6, q7,   [sp, #SIMD_AREA + 96]
    ldp     q4, q5,   [sp, #SIMD_AREA + 64]
    ldp     q2, q3,   [sp, #SIMD_AREA + 32]
    ldp     q0, q1,   [sp, #SIMD_AREA + 0]

    ldr     x30, [sp, #240]
    ldp     x28, x29, [sp, #224]
    ldp     x26, x27, [sp, #208]
    ldp     x24, x25, [sp, #192]
    ldp     x22, x23, [sp, #176]
    ldp     x20, x21, [sp, #160]
    ldp     x18, x19, [sp, #144]
    ldp     x16, x17, [sp, #128]
    ldp     x14, x15, [sp, #112]
    ldp     x12, x13, [sp, #96]
    ldp     x10, x11, [sp, #80]
    ldp     x8, x9,   [sp, #64]
    ldp     x6, x7,   [sp, #48]
    ldp     x4, x5,   [sp, #32]
    ldp     x2, x3,   [sp, #16]
    ldp     x0, x1,   [sp, #0]
    add     sp, sp, #CTX_SIZE
    ret

fast_passthrough:
    svc     #0
    ret

fast_path_sigreturn:
    svc     #0
    ret
