# FD metadata core checks

Run `python3 test/fd_table/run.py` from the repository root, or `make check`.
The test compiles the exact metadata core as a freestanding C object and checks
that the optimized object has no undefined runtime dependencies. A separate
libc-hosted harness runs model transitions and native kernel comparisons.

Covered: provenance replacement, RO/RW/unknown tags, distinct opens, shared dup
identity, descriptor flags, reuse generations, sparse/high FD numbers, capacity
and counter overflow, error atomicity, range close/CLOEXEC, copy independence,
and exec filtering. Native comparisons exercise memfd, dup, dup3, F_DUPFD,
F_DUPFD_CLOEXEC, F_SETFD, shared offsets, fork and actual exec.

These are not runtime integration or permission tests. No SVC interception,
CLONE_FILES notification, concurrency, guest exec handoff or readonly enforcement
is connected yet. Range transitions are model-only; native close_range is not
probed by this test. Kernel events are applied manually by the harness after
successful syscalls. A future adapter must arrange capacity and synchronization
before exposing new FDs, and handle Linux close error semantics separately.

The snapshot/transport tests compile `fd_snapshot.c` and `fd_handoff.c` directly.
They exercise unaligned versioned buffers, CLOEXEC filtering, duplicate and
conflicting records, short/oversized inputs and atomic failure. The exact
transport module creates sealed memfds and restores metadata after real exec;
a libc shim implements its raw_syscall interface. Fault injection verifies
write/seal failure FD cleanup, read errors, EINTR and partial transfers.
An inherited transport FD is explicitly closed by its owner after restore.

The test does not accept external snapshots as trusted permissions. Seals are
immutability, not authentication. Loader integration and live FD identity
validation remain outstanding. No rootfs runtime behavior changes in this step.

`python3 test/fd_table/check_clone.py` separately runs a freestanding SVC probe
both natively and through the built ELF loader. Six VM/FILES/THREAD combinations
check close, CLOEXEC, new descriptors, shared file offsets, PID and memory.
Parent/child synchronization checks visibility before child exit. Ordinary
processes are reaped; threads use CHILD_CLEARTID and exit rather than exit_group.

On the tested terminal sandbox, non-thread CLONE_FILES requests still copy the
FD table, and threads without CLONE_FILES still share it. Default mode reports
these three host deviations explicitly while requiring native/loader parity.
Use `--strict-linux` to fail on the deviations. The default passing result is
compatibility parity, not full Linux clone conformance or metadata integration.
The report is `vendor/proot/svc/build/clone-fd-results.json` (ignored by Git).

`check_notify.py` links the production clone assembly and transaction manager
with observable callbacks. It uses real clone, separate and inherited stacks,
vfork, forced child-first notification, kernel errors, observer rejection,
allocation failure and 64 clones from four concurrent callers. Register, SP,
SIMD and FP state preservation are checked in assembly. This validates the
runtime notification seam; it does not validate an FD metadata manager.
`check_payload_abi.py` checks v3 custom payload startup and rejects v2/invalid
versions before guest execution. Both checks are included in `make check`.

The notification tests also sweep concurrently, pause a live callback, abandon
parent and child callbacks via real task exit, inject uncertain tgkill errors,
and verify unknown-child retention. They exhaust/reuse the 64-slot shared pool
and abandon more than 64 children to exercise automatic reclamation. Reentrant
first initialization verifies losing-mapping cleanup. Kernel task disappearance
is awaited separately from pthread_join. A shared resource arena now checks exactly one cookie retirement after both
roles and all readers finish, including rejected preparation and kernel errors.
Dedicated modes pause cleanup while exhausting capacity, reenter cleanup, and
exit inside cleanup to verify that destruction is not retried. They do not
establish process-local FD cleanup or recovery of abandoned initialization,
reaper pins or finalizers.

`check_fd_clone.py` connects `fd_clone.c` and `fd_table.c` to the real clone
notification assembly in a dedicated harness. Six host modes each run parent-
and child-first publication. Actual CLOEXEC/close effects are compared with
snapshot/shared metadata; capacity errors, identity conflicts, failed clones and
rejected preparation are covered. A native SVC probe verifies this host's child
thread x29 reset before enabling that fixture expectation. This test is host-
specific, not a portable inference of CLONE_FILES semantics. It does not enable
payload FD interception, global task registration or concurrent FD mutations.

The real FD clone harness now reserves/publishes through `fd_registry.c` and
retires handles after kernel task exit. Failed/rejected clones cancel their
reservation from cookie cleanup. Registry storage is preallocated MAP_SHARED;
handshakes serialize operations, so this is not a concurrent registry test.
`registry.c` separately checks task/table capacity, copied snapshots, shared
ownership, cancellation, last-owner recycling, stale handles after slot/TID
reuse and generation overflow. No default payload FD interception is enabled.

`guard.c` uses the production nonwaiting `fd_guard.c` to serialize 8,000 registry
and table transactions across four threads. Real signal reentry, stale/duplicate
leases, fork-inherited ownership, dead-owner retention and generation exhaustion
are checked. A freestanding object check requires no undefined symbols. Test
retries and deliberate fork/exit while holding a lease are harness coordination
and fault injection, not supported production usage. The guard must not span
syscalls or callbacks; these tests do not solve syscall/bookkeeping atomicity.
