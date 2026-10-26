# Syscall engine constraints and regression requirements

This engine reuses the system sandbox. It implements guest filesystem semantics
through patched SVC sites; it does not provide kernel namespace isolation.

## History that must survive refactoring

- `4352500` introduced a selector for calls requiring instrumentation. There
  is no historical benchmark explaining the choice. Saving 768 bytes of CPU
  context and acquiring a global lock on every syscall is nevertheless a
  concrete cost; any claimed speedup still needs measurement.
- `fd91d2f` introduced reentry protection to prevent recursive hooks. It is
  originally keyed by TPIDR_EL0, with 32 slots and a global spinlock. A full table or
  nonzero depth caused passthrough. Slots were not reclaimed on thread exit.
- `f1cde57` explicitly fixed new-thread SIGSEGV by moving stub register saves
  from colliding TLS slots to the stack.
- `e1c7902` added clone passthrough in the stub, before changing SP.
  rt_sigreturn likewise bypasses before the stack is touched. Clone can change
  the child's stack; rt_sigreturn consumes a kernel signal frame. Restoring
  only entry.S's stack frame would still leave the stub's 32-byte frame.
- `a3d1240` removed exit/exit_group from slow dispatch. Its message did not
  separately explain this removal. Source analysis shows why it matters now:
  a successful exit cannot return to reentry_leave. Reusing that thread's TLS
  address can leave another thread permanently classified as reentrant.

## Correction to the all-number experiment

`47dcc5f` sent ordinary calls into slow dispatch. The 1022-number sentinel test
proved only direct entry routing. It did not traverse generated stubs, verify
thread lifecycle or measure performance. Its claim that actual guest clone
entered a preflight dispatcher was wrong: the stub still bypassed it.
Native/loader clone success validated the existing stub bypass instead.

The replacement keeps an explicit `slow_syscalls.inc` inventory. Existing
handled calls and filesystem/FD/mapping/namespace interfaces enter the C layer;
ordinary unrelated calls and unknown numbers remain fast passthrough. rt_sigreturn
retains its original-stack bypass; exit/exit_group remain outside the guard.
PRoot clone now uses a dedicated original-SP notification path (see below),
not the ordinary C dispatcher. Legacy clone retains its original stub bypass.
No FD permission policy is enabled by these notifications.

The inventory is routing, not a support or security allowlist. Adding read,
write or other blocking FD calls also lengthens the period with depth=1;
signal-handler syscalls during that period may take the reentry bypass.
Signal interruption while holding the guard lock can also deadlock on reentry.
These are source-derived risks, not newly reproduced failures. Selective
routing does not fix them; the guard needs a separate lifecycle/concurrency
redesign before hostile-code isolation can be claimed.

## Rules for future changes

1. Read the whole SVC -> generated stub -> entry -> guard -> dispatcher chain.
   A unit test calling entry directly cannot prove stub routing.
2. Keep syscall numbers tied to target ABI headers. A native SIGSYS result is
   not a numbering error and is not ordinary ENOSYS.
3. Survey native calls in isolated subprocesses with explicit arguments.
   EBADF/EINVAL establish behavior only for those arguments. Never infer full
   kernel support from a header or a single invalid-argument test.
4. Distinguish routing, implementation and validation. VFS adaptation includes
   paths, dirfds, flags, symlink behavior, errno and actual filesystem effects.
5. Prefer native fixture controls for platform differences. Do not report
   chmod mode fidelity or successful hardlinks when the host cannot show them.
6. Cover both operands for link/rename, descriptor identity after rename and
   deletion, and process/thread inheritance before implementing policy on top.
7. Do not replace kernel errors with fake success in the experimental path
   backend. Compatibility fakeroot must eventually be a separate explicit mode.
8. Preserve raw-syscall and reentry bypass findings in reports. Broad dispatch
   does not close these bypasses or complete default-deny/read-only enforcement.

## Required tests

- `test/syscalls/check_dispatch.py`: header ABI constants, selected slow calls,
  special/unrelated exclusions, actual fast getpid/unknown and exit routing.
- `test/syscalls/check_runtime.py`: native and loaded signal delivery/return,
  clone with a new stack, and six sandbox-fatal recipes returning ENOSYS.
- `test/svc_probe/run.py`: generated SVC hooks and known raw-entry bypass.
- `vendor/proot/port-tests/test_svc.py`, `test_exec.py`, `test_modify.py`:
  filesystem behavior, exec continuity and native metadata mutation controls.
- `make -C vendor/proot/svc check`: independent path/binding semantics.

Still needed: concurrent threads and guard exhaustion/TLS reuse, signals during
blocking calls/lock ownership, FD provenance, complete directory views, dynamic
brew executable coverage, and performance measurements.

## Filesystem scope and performance direction

The agreed scope is a filesystem view and access-control layer, not a complete
userspace filesystem. The host kernel should retain responsibility for file
contents, ordinary I/O, inode operations and storage caching. These are design
constraints for upcoming work, not claims about optimizations already shipped.

- Path operations translate guest paths and check policy before issuing the
  host syscall. Preserve symlink, dotdot and dirfd semantics; simple textual
  prefix substitution is not sufficient.
- Record necessary mount identity and permissions when acquiring descriptors.
  Prefer lightweight FD checks followed by native read/write rather than
  repeated path walks or userspace file-content copies. Account for inherited,
  duplicated and transferred FDs and writable mappings before relying on this.
- Pass ordinary directory reads to the kernel. Transform getdents output only
  where visibility filtering or synthetic mountpoint entries require it.
- Keep overlay/copy-up and merged-directory processing optional and out of the
  ordinary bind path.
- Initialize immutable mapping tables once per configuration. Replace per-call
  scratch mmap/munmap only with storage whose thread and signal reentry
  ownership is defined. Distinguish full path handling from lightweight FD
  handling rather than requiring identical work for every selected syscall.
- Cache immutable configuration matching where useful. Do not cache filesystem
  resolution without an invalidation model for rename and symlink changes.

The current prototype still allocates path scratch and constructs bindings per
call and uses full register save/restore on selected slow calls. Establish
native-vs-loader benchmarks for path lookup, open/stat, FD I/O and directory
reads before claiming improvements. Semantics and policy checks must survive
optimization; broad dispatch alone does not enforce access control.


## Active-call guard update

The guard now uses raw gettid and atomically claimed active-call slots. It
releases the slot after each returning slow call, has no global spinlock and
never reads guest TLS. Same-thread recursion still returns NULL and follows
the existing reentry bypass. Capacity exhaustion returns -EAGAIN through the
assembly error path, without issuing the guest syscall. There are still 32
simultaneous slots; ordinary entry performs no allocation or unbounded wait. A failed
claim can conservatively return EAGAIN even if another slot becomes free.

`test/syscalls/check_guard.py` covers 1024 sequential owner identities, nested
entry, full capacity and recovery, an occupied owner after a free hole, eight
real concurrent threads and asynchronous signals during entry/leave. Owner
identity/capacity cases use a test raw-gettid adapter; thread/signal tests use
real kernel TIDs. The assembly selector test injects a guard error to prove
that exhaustion is returned rather than passed through. The runtime and full
filesystem regressions also pass. This adds a gettid syscall per slow entry;
no performance improvement is claimed without measurements.

Remaining lifecycle limitations: nonlocal exits from signal handlers can
abandon slots; abnormal thread/process termination can leave owners behind; TID reuse
can matter after an abandoned owner. A guest signal during an active hook
still bypasses through the same-thread recursion rule. These require explicit
signal/fork/lifecycle handling, not more slots or a silent fallback. The new
stress test does not prove arbitrary signal-handler safety or hostile-code
isolation.


## Fork ownership update

A real fork regression reproduced stale copied owners: with 32 active slots,
the parent released all owners after fork but the child kept returning EAGAIN.
The active table now resides in one MAP_SHARED|MAP_ANONYMOUS mapping, lazily
published by atomic CAS. Parent releases therefore reach the child's view.
Shared-address-space clone users share the same table without PID-based resets
that could erase another live owner's slot. No per-call mapping is added.

Initialization failures return errno and remain retryable. Competing or nested
initializers unmap the losing candidate. Tests cover mapping failure/retry,
deterministic nested initialization, concurrent first use, and actual fork
with parent-held owners (synthetic owner IDs provide deterministic full-table
setup). The original implementation fails the fork fixture with child exit 13;
the shared table passes it along with existing guard and loader regressions.

The 32-slot budget is now shared across processes inheriting that mapping, not
32 independent slots per fork child. Slow calls may return EAGAIN under that
combined load. An active owner that exits abnormally can still consume capacity
in surviving processes. SIGKILL, nonlocal signal exits and safe dead-owner
reclamation are unresolved; no liveness guarantee is made for those cases.
The mapping lives until all inheritors unmap it or exit; exec installs a new
payload and guard. Performance and full CLONE_VM lifecycle remain unbenchmarked.

## Dedicated clone notification path (PRoot payload ABI 3)

The generated PRoot clone stub enters a separate gate at payload entry +16.
`clone_entry.S` saves GPR/SIMD/FP state, prepares a per-call shared transaction,
then restores registers and the original guest SP BEFORE executing clone SVC.
Only x9 temporarily carries the transaction pointer across the kernel call;
it is restored before the guest continues. Clone arguments, including child SP,
flags, TLS and TID pointers, are not rewritten.

After SVC, each returning task uses its own current stack for notification.
It never returns through a parent's saved C frames on the child's new stack.
The stub-local direct branch restores x16/x17 and original SP without sacrificing
a register for the guest return address. rt_sigreturn still bypasses all frames.
Direct payload-entry clone callers and legacy stubs retain their old bypass;
only generated PRoot stubs use the notification gate.

`clone_notify.c` supplies before/finish observer seams. They are no-ops in the
current runtime, not FD snapshot publication or permission checks. Before may
reject with negative errno, without executing clone. A successful clone may
notify child first; a kernel error only notifies the original caller. Shared
VMs and copied VMs complete roles in the same inherited shared pool. Do not
infer FD sharing from this context storage rule.

Tests execute the real assembly and observers with NULL/new child stacks,
vfork, intentional child-first notification, kernel error, preparation rejection,
allocation failure and four simultaneous callers (64 clones). They verify SP,
x2-x19/x22-x30, preserved child-SP and parent-SP values, every SIMD lane, FPCR
and FPSR; raw syscall return x0 is checked by the caller. The generated stub
is separately covered by the six native/loader clone scenarios. ABI tests
accept a v3 custom payload and reject v2/invalid versions before guest startup.

Costs/limits: one lazily published shared pool with 64 concurrent transactions
across the inheriting clone family; no per-clone mmap/munmap. No benchmark yet.
Notifications use about 800 bytes of assembly context plus C stack on each
returning task, requiring an ABI-aligned usable stack; arbitrary tiny/unaligned
raw-clone stacks are not validated. On exhaustion, a reaper uses tgkill(pid, tid, 0) and completes missing roles only
on ESRCH, then retries allocation; otherwise prepare returns EAGAIN. Pins prevent
slot reuse while concurrent reapers inspect identities. EPERM and other errors
never establish death. This reclaims known dead parents/children even when they
exit inside the observer. Final retirement now invokes the cleanup seam below.

Unknown child identity, interrupted initialization, abandoned reaper pins and
nonlocal escapes/exec in still-live tasks can still strand slots. PID reuse may
delay reclamation. The pool is bounded, not a guarantee of eventual progress.
Only inherited shared metadata may use the cleanup seam; process-local FD
resources still need their own ownership/cancellation protocol.
FD snapshot consistency, process registration and exec handoff remain required
before enabling FD policy. This is not a security-boundary fix.

Tests also cover reentrant pool initialization, concurrent sweeps, a live child
paused inside its callback, known dead parent/child callbacks, injected uncertain
liveness errors, unknown-child retention, capacity exhaustion/reuse and repeated
child abandonment beyond capacity. pthread_join on this host can return before
tgkill observes ESRCH; the unknown-child fixture waits for kernel disappearance
before asserting reclamation, rather than weakening the runtime death check.


## Clone cookie retirement

`clone_observer_cleanup(event, reasons)` takes over a cookie once before returns,
including rejection. Finish never frees it. A CAS elects a unique finalizer only
after both roles and all reaper pins finish; the slot stays unavailable throughout
cleanup. The finalizer may run in parent, child or another inheriting reaper.
Reapers retain their pin while recording only newly abandoned roles, so stale
liveness checks cannot label an already normally completed role as abandoned.
A negative kernel result establishes no child, not an abandoned child.

Cookies must reference storage inherited and accessible across this clone family
(e.g. a preallocated shared arena). One callback in one VM cannot unmap every
fork-inherited mapping or close another process's descriptor. Do not use private
heap pointers or later-created mappings as globally finalizable cookies.
The callback must return without blocking and tolerate reentry. Its death or
nonlocal escape strands the slot: retrying potentially completed side effects
would risk duplicate destruction. Unknown-child and interrupted-before cases
still cannot be safely finalized. This is shared metadata retirement, not a
complete FD lifecycle implementation or stronger isolation.

The real-clone harness uses a shared resource arena and checks one retirement per
transaction, preparation rejection, kernel failure, child-first return, live
callback retention, abandoned parent/child and unknown-child retention. Separate
fixtures pause cleanup while filling the pool, reenter from cleanup, and kill a
finalizer; the last case retains capacity rather than retrying destruction.


## FD clone snapshot integration fixture

The new `fd_clone.c` transaction prepares a copied table or explicit shared
reference before clone and publishes a single child identity idempotently from
either return. Real callbacks test six native host modes in both publication
orders against actual CLOEXEC and close effects. Source stability, arena storage,
registry ownership, TID reuse and arbitrary concurrent mutations remain caller
responsibilities; the module is not enabled in the default payload.

Extending the register fixture to CLONE_THREAD exposed child x29=0 on this host.
A separate libc-free native clone probe reproduces it without the ELF engine.
The FD clone fixture checks that native behavior before expecting zero only for
thread children. Existing non-thread register tests remain unchanged, and the
production trampoline still restores the kernel-returned context.


## Registry ownership before runtime synchronization

`fd_registry.c` reserves task/table capacity before clone, maintains explicit
copied/shared ownership, and identifies owners by slot plus generation. Task
exit retirement requires the matching handle, confirmed exit and no remaining
notification/readers; a TID lookup alone is not authorization to free storage.
Last-owner recycling clears old provenance on reuse. A child's cookie cleanup
cancels unpublished reservations, but must not free an adopted live table.

The caller supplies inherited storage and serialized access. The module has no
lock across clone and no implicit claim of reentrant or concurrent safety.
Real-clone tests use handshake ordering, then wait for kernel task disappearance
before retiring a handle. Arbitrary signal reentry, concurrent FD operations,
unknown exits and exec still require a runtime synchronization/lifecycle layer.


## Nonwaiting metadata exclusion is not syscall atomicity

The existing slow-path reentry guard admits multiple tasks and bypasses same-TID
reentry; it cannot serialize registry/table mutation. `fd_guard.c` instead uses
one lock-free 64-bit CAS containing TID and a 32-bit lease generation. Contention
and recursion return immediately, stale releases cannot unlock later ownership,
and generation exhaustion fails rather than wraps. Caller-provided TIDs must be
actual kernel identities in the same namespace. No automatic dead-owner reset
is safe because a terminated owner may have partially changed metadata.

Four threads perform 8,000 protected registry/table transactions; a real signal
handler verifies EDEADLK, and fork fault injection checks inherited shared state
and dead-owner retention. The production primitive never waits; test coordination
may retry outside it. This is not a benchmark or an end-to-end FD race test.

Only metadata-only sections may hold the guard. Keeping it across clone, blocking
syscalls or callbacks risks deadlock/progress failure. Releasing it around kernel
operations creates a different issue: a successful close/open cannot be undone
by returning EAGAIN on later bookkeeping. Runtime integration needs reservations,
operation identity and a result-commit protocol. The new module is not linked to
the default payload, and existing reentry bypass behavior remains unchanged.


## Close completion must not delete a later FD incarnation

A close may succeed, then another thread can reuse its descriptor number and
publish new metadata before the first thread commits removal. Unconditional
`fd_table_close` would erase the new provenance. The new generation-checked
variant leaves a newer record unchanged and reports ESTALE; absent records are
already reconciled, and a captured unknown generation cannot delete a newly
tracked descriptor. A pthread fixture uses actual close/dup3 and verifies that
the replacement /dev/zero FD remains readable after delayed bookkeeping.

This protects only metadata completion ordering. A generation snapshot is not a
kernel FD pin: reuse before kernel entry is a separate race. The same table
incarnation must remain alive, and every lookup/commit requires exclusion.
ESTALE must not overwrite the kernel result or trigger a retry of kernel close.
Kernel error classification and reliable commit after guard contention remain
unimplemented. Existing unconditional model operations remain for fully ordered
events; neither API is enabled in default payload interception yet.


## Reserve close bookkeeping before kernel entry

`fd_close_queue.c` reserves bounded inherited storage and pins a registry owner
before close. Outcome publication is a single atomic state transition with a
generation ticket; it neither takes the metadata guard nor allocates memory.
Later drain under exclusion applies generation-checked removal and drops the
owner pin. Retirement cannot recycle the table while a result is outstanding.
Reservations and ready results both count as pending for cooperating adapters.

A real close test publishes while another thread owns the guard, then drains
once. It also checks shared-table overlap, capacity exhaustion, stale tickets,
KEEP cancellation, generation overflow and newer-record preservation. The
kernel close is never repeated to resolve a bookkeeping conflict.

KEEP/REMOVE are caller-established effects, not an errno classification. An
unknown result or dead reserver remains pinned; no guessed cleanup is safe.
Prepare/query/drain still require exclusion; only publication is concurrent.
Drain errors may occur after earlier slots committed, and nonlocal death while
mutating metadata must not be followed by blindly clearing its guard. No default
payload interception, pre-kernel reuse prevention across uncooperative callers,
close error adaptation or automatic abandoned-operation recovery is enabled.


## Executable close adapter and conservative outcome handling

`fd_close_execute` ties actual TID/handle validation, guarded preflight, queue
reservation, one raw close, lock-free publication and best-effort drain together.
Metadata status is separate from the kernel return after invocation. A later
entry may drain earlier results but never re-executes those close syscalls.
Native success and EBADF are checked in the integration fixture. Both permit
removing matching old metadata; EBADF must not leave stale authorization alive.
All other kernel results remain pending with EINPROGRESS bookkeeping status.

The harness injects guard contention and uncertain EINTR/EACCES/EIO outcomes;
these validate control flow, not native error semantics. Unknown outcomes keep
pins and can exhaust capacity. No passthrough/retry fallback is provided. This
adapter still runs only in the harness, not the default dispatcher: registry
startup and all cooperating FD/clone/exec adapters must precede activation.
