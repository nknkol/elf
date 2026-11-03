/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PAYLOAD_STACK_H
#define PAYLOAD_STACK_H
/* Stacks for the intercepted calls (arch/aarch64/payload_stack.c), mapped
 * when first claimed. More threads in calls at once than stacks: those run
 * on their own stack. */
#define PAYLOAD_STACKS 64
#define PAYLOAD_STACK_SIZE (64 * 1024)
/* The top of a stack now owned by this thread, or 0 (none free, or this
 * thread is on one already). */
void *payload_stack_claim(void);
void payload_stack_release(void *top);
void payload_stack_clone_finish(unsigned long flags, long result);
#endif
