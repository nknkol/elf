#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include "syscall_nums.h"
#include "dispatch.h"
#include "integrity.h"
#include "config.h"
#include "proot_bridge.h"
#include "container_state.h"
#include "union_view.h"
#include "fake_ids.h"
#include "host_syscall.h"
#ifdef GUARDED
#include "fd_runtime.h"
#define DISPATCH(n, args) fd_runtime_dispatch(n, args)
#else
#define DISPATCH(n, args) dispatch_syscall(n, args)
#endif

typedef struct {
    unsigned long regs[30]; // x0 - x29
    unsigned long lr;       // x30
    unsigned long _pad;
} pt_regs;

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

/* The intercepted calls run on a stack of the payload's: a vfork child may
 * run on musl's posix_spawn stack, about 5 KiB, which path walking, the
 * broker and the guard would overrun into the suspended parent's frame.
 * A stack is claimed by thread id and given back on return; the parent of
 * a vfork child that exec'd gives back what the child held when vfork
 * returns (the memory is shared), and a forked child starts with none
 * claimed. None free (or already on one): the current stack. Signals are
 * blocked while the payload runs, so no guest handler runs on it. */
#define PAYLOAD_STACKS 8
#define PAYLOAD_STACK_SIZE (64 * 1024)
static struct payload_stack { long owner; void *base; } payload_stacks[PAYLOAD_STACKS];
extern long call_on_stack(long (*fn)(void *), void *arg, void *top);

static struct payload_stack *claim_stack(long tid)
{
    for (int i = 0; i < PAYLOAD_STACKS; i++)
        if (__atomic_load_n(&payload_stacks[i].owner, __ATOMIC_RELAXED) == tid)
            return 0; /* Already on it (a nested call). */
    for (int pass = 0; pass < 2; pass++)
    for (int i = 0; i < PAYLOAD_STACKS; i++) {
        /* Second pass: stacks of threads that exited holding them (a thread
         * that unmapped its own stack exits from the payload). */
        if (pass) {
            long owner = __atomic_load_n(&payload_stacks[i].owner, __ATOMIC_RELAXED);
            if (owner > 0 && raw_syscall(__NR_tgkill, raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0),
                                         owner, 0, 0, 0, 0) == -ESRCH)
                __atomic_compare_exchange_n(&payload_stacks[i].owner, &owner, 0, 0,
                                            __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        }
        struct payload_stack *s = &payload_stacks[i];
        long free_owner = 0;
        if (!__atomic_compare_exchange_n(&s->owner, &free_owner, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            continue;
        if (!s->base) {
            long mem = raw_syscall(__NR_mmap, 0, PAYLOAD_STACK_SIZE, 3, 0x22, -1, 0);
            if ((unsigned long)mem >= (unsigned long)-4095) {
                __atomic_store_n(&s->owner, 0, __ATOMIC_RELEASE);
                return 0;
            }
            s->base = (void *)mem;
        }
        return s;
    }
    return 0;
}

void payload_stack_clone_finish(unsigned long flags, long result)
{
    if (result < 0)
        return;
    for (int i = 0; i < PAYLOAD_STACKS; i++) {
        if (!result && !(flags & 0x100 /* CLONE_VM */)) {
            /* A private copy: the claims are other threads' of the parent. */
            payload_stacks[i].owner = 0;
        } else if (result && (flags & 0x4000 /* CLONE_VFORK */)) {
            long child = result;
            __atomic_compare_exchange_n(&payload_stacks[i].owner, &child, 0, 0,
                                        __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        }
    }
}

struct dispatch_call { long sys_no; pt_regs *regs; };
static long dispatch_here(long sys_no, pt_regs *regs);
static long dispatch_run(void *opaque)
{
    struct dispatch_call *c = opaque;
    return dispatch_here(c->sys_no, c->regs);
}

long syscall_dispatcher(long sys_no, pt_regs *regs)
{
    struct payload_stack *stack = claim_stack(raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0));
    if (!stack)
        return dispatch_here(sys_no, regs);
    struct dispatch_call call = {sys_no, regs};
    long ret = call_on_stack(dispatch_run, &call, (char *)stack->base + PAYLOAD_STACK_SIZE);
    __atomic_store_n(&stack->owner, 0, __ATOMIC_RELEASE);
    return ret;
}

static long dispatch_here(long sys_no, pt_regs *regs)
{
    long *a = (long *)regs->regs;
    /* A thread unmapping the stack it entered on (musl's __unmapself: munmap
     * then exit, touching no stack): nothing can return to it, since the
     * entry saved the registers there. Its only next step is exit. */
    if (sys_no == __NR_munmap && (unsigned long)regs - (unsigned long)a[0] < (unsigned long)a[1]) {
        long rc = raw_syscall(__NR_munmap, a[0], a[1], 0, 0, 0, 0);
        if (!rc)
            raw_syscall(__NR_exit, 0, 0, 0, 0, 0, 0);
        return rc;
    }
    /* The backends may rewrite their copy; the saved registers stay. */
    long args[6] = {a[0], a[1], a[2], a[3], a[4], a[5]};
    long ret;

    if (sys_no >= __NR_setxattrat && sys_no <= __NR_file_setattr)
        return -ENOSYS; /* Untranslated newer path calls (syscall_nums.h). */
    if (integrity_check(sys_no, a, &ret))
        return ret;
    int named = sys_no == __NR_accept || sys_no == __NR_accept4 ||
        sys_no == __NR_getsockname || sys_no == __NR_getpeername;
    unsigned capacity = named && a[1] && a[2] ? *(unsigned *)a[2] : 0;
    ret = DISPATCH(sys_no, args);
    /* R6: a directory of the merged view lists every layer. */
    if (sys_no == __NR_getdents64 && union_enabled())
        ret = union_getdents((int)a[0], (void *)a[1], (unsigned long)a[2], ret);
    /* A batch holding only the payload's FDs is read again: zero means the
     * end of the directory. */
    while (sys_no == __NR_getdents64 && ret > 0 && !(ret = broker_hide_fds((int)a[0], (void *)a[1], ret))) {
        long again[6] = {a[0], a[1], a[2], a[3], a[4], a[5]};
        ret = DISPATCH(sys_no, again);
    }
    if (!ret) {
        fake_ids_stat_owner(sys_no, a);
        owners_stat(sys_no, a); /* R5: recorded owners and modes */
    }
    /* struct utsname: six 65-byte fields; sysname, nodename, release. */
    if (!ret && sys_no == __NR_uname && a[0]) {
        if (g_payload_config.kernel_sysname[0])
            memcpy((char *)a[0], g_payload_config.kernel_sysname, 65);
        if (g_payload_config.hostname[0])
            memcpy((char *)a[0] + 65, g_payload_config.hostname, 65);
        if (g_payload_config.kernel_release[0])
            memcpy((char *)a[0] + 130, g_payload_config.kernel_release, 65);
    }
    if (ret >= 0 && capacity)
        proot_socket_name(sys_no, sys_no == __NR_accept || sys_no == __NR_accept4 ? ret : a[0],
                          (void *)a[1], (unsigned *)a[2], capacity);
    return ret;
}
