/* Exercise the actual entry.S with a deterministic dispatcher test double.
 * No kernel call is made for tested numbers, including unknown numbers. */
.text
.global _start
_start:
    mov x19, #0
1:
    cmp x19, #139
    b.eq 3f
    cmp x19, #220
    b.eq 3f
    mov x8, x19
    mov x0, #71
    bl hook_entry
    add x20, x19, #1024
    cmp x0, x20
    b.ne 4f
3:
    add x19, x19, #1
    cmp x19, #1024
    b.lt 1b
    mov x0, #0
    b 5f
4:
    mov x0, #1
5:
    mov x8, #94
    svc #0
.global syscall_dispatcher
syscall_dispatcher:
    add x0, x0, #1024
    ret
.global reentry_try_enter
reentry_try_enter:
    mov x0, #1
    ret
.global reentry_leave
reentry_leave:
    ret
.data
.global g_payload_config
g_payload_config:
    .quad 0
