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
