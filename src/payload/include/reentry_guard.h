/* Ownership lasts only for one active slow-path call, keyed by kernel TID. */
#ifndef REENTRY_GUARD_H
#define REENTRY_GUARD_H
struct reentry_slot;
/* Slot on success; NULL for same-thread recursion; negative errno pointer
 * on failure/capacity exhaustion. Callers must distinguish all three. */
struct reentry_slot *reentry_try_enter(void);
/* Single nonnested vfork child only. Begin before it can enter guest code;
 * end only after kernel vfork return proves it left this VM (or clone failed).
 * These manage a dedicated slot and never reclaim shared-pool owners by TID. */
void reentry_vfork_begin(long tid);
void reentry_vfork_end(void);
/* Call only in a confirmed private-VM fork child before entering guest code.
 * Resets its copied slot without touching the parent's active ownership. */
void reentry_private_fork(long tid);
void reentry_leave(struct reentry_slot *slot);
#endif
