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
ordinary unrelated calls and unknown numbers remain fast passthrough. clone
and rt_sigreturn retain the original-stack stub paths. exit/exit_group remain
outside the guard. There is no clone policy preflight at present.

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
simultaneous slots; no allocation or unbounded wait is introduced. A failed
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
abandon slots; fork can inherit active owners from other threads; TID reuse
can matter after an abandoned owner. A guest signal during an active hook
still bypasses through the same-thread recursion rule. These require explicit
signal/fork/lifecycle handling, not more slots or a silent fallback. The new
stress test does not prove arbitrary signal-handler safety or hostile-code
isolation.
