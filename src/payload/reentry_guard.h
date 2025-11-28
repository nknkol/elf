/* Simple per-thread reentry guard built on top of tpidr_el0.
 * Keeps a small slot table so hooks can bail out if already on the stack.
 */
#ifndef REENTRY_GUARD_H
#define REENTRY_GUARD_H

struct reentry_slot;

struct reentry_slot *reentry_try_enter(void);
void reentry_leave(struct reentry_slot *slot);

#endif /* REENTRY_GUARD_H */
