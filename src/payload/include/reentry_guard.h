/* Ownership lasts only for one active slow-path call, keyed by kernel TID. */
#ifndef REENTRY_GUARD_H
#define REENTRY_GUARD_H
struct reentry_slot;
/* Slot on success; NULL for same-thread recursion; negative errno pointer
 * on failure/capacity exhaustion. Callers must distinguish all three. */
struct reentry_slot *reentry_try_enter(void);
/* Borrowed current slot; only a proven nonreturning owner may be released elsewhere. */
struct reentry_slot *reentry_current(void);
void reentry_leave(struct reentry_slot *slot);
#endif
