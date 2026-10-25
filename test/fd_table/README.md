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
