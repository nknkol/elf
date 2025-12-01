/* userlandexec/test_hello/tiny_target.S */
.text
.global _start

_start:
    /* 测试点 1: 模拟 write 系统调用 */
    mov x0, 1           /* fd = stdout */
    ldr x1, =msg_start  /* buf */
    mov x2, len_start   /* count */
    mov x8, 64          /* sys_write */
    svc #0              /* <--- Loader 将会 Hook 这里 */

    /* 测试点 2: 模拟 exit 系统调用 */
    mov x0, 0           /* status */
    mov x8, 93          /* sys_exit */
    svc #0              /* <--- Loader 将会 Hook 这里 */

.section .rodata
msg_start: .ascii ">>> Tiny Target Running...\n"
len_start = . - msg_start