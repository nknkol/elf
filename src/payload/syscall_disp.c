#include "mini_libc.h"

/* Syscall Numbers */
#define SYS_getcwd      17
#define SYS_faccessat   48
#define SYS_openat      56
#define SYS_close       57
#define SYS_read        63
#define SYS_write       64
#define SYS_newfstatat  79
#define SYS_exit        93
#define SYS_exit_group  94
#define SYS_rt_sigreturn 139
#define SYS_execve      221
#define SYS_mprotect    226

#define SAFE_LOG(msg) do { \
    static const char _buf[] = msg; \
    sys_write(1, _buf, sizeof(_buf) - 1); \
} while (0)

typedef struct {
    unsigned long regs[30]; // x0 - x29
    unsigned long lr;       // x30
    unsigned long _pad;
} pt_regs;

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);
unsigned long sys_strlen(const char *s);

static void log_hex_safe(unsigned long val) {
    char buf[19];
    char map[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    
    buf[0] = '0'; buf[1] = 'x';
    for(int i = 0; i < 16; i++) {
        buf[17 - i] = map[val & 0xf];
        val >>= 4;
    }
    buf[18] = 0; // Null terminator? No, we use count 18.
    sys_write(1, buf, 18);
}

static inline long do_syscall(long sys_no, long *a) {
    return raw_syscall(sys_no, a[0], a[1], a[2], a[3], a[4], a[5]);
}

long syscall_dispatcher(long sys_no, pt_regs *regs) {
    long ret;
    long *a = (long *)regs->regs;

    /* Special case: infinite loop prevention */
    if (sys_no == SYS_write) {
        return raw_syscall(sys_no, a[0], a[1], a[2], a[3], a[4], a[5]);
    }

    switch (sys_no) {
        case SYS_getcwd:
            SAFE_LOG("[Payload] getcwd\n");
            ret = do_syscall(sys_no, a);
            break;

        case SYS_openat:
            SAFE_LOG("[Payload] openat\n");
            ret = do_syscall(sys_no, a);
            break;
            
        case SYS_faccessat:
            SAFE_LOG("[Payload] faccessat\n");
            ret = do_syscall(sys_no, a);
            break;

        case SYS_exit:
        case SYS_exit_group:
            SAFE_LOG("[Payload] exit\n");
            ret = do_syscall(sys_no, a);
            break;

        default:
            ret = do_syscall(sys_no, a);
            break;
    }

    return ret;
}
