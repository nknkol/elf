# Single-task FD runtime experiment

Run from the repository root:

```sh
make check-fd-runtime
vendor/proot/svc/build/elfloader-proot-fd-experiment --mode compat -- /path/to/program
```

This builds a separate executable and manifest. Normal `make build`/`make check`
continue to produce `elfloader-proot` with the existing behavior. Both builds
share intermediate object paths, so do not build them concurrently. The last
build also determines `src/elfloader`; prefer the named snapshots above.

The experimental payload initializes a single-task registry on first slow call,
tracks up to 128 descriptors from openat, memfd_create, eventfd2, epoll_create1,
timerfd_create, pipe2, socket, socketpair, accept, accept4, dup, dup3,
F_DUPFD/F_DUPFD_CLOEXEC and
F_SETFD, and routes close through reserved outcome bookkeeping. Inherited FDs
start untracked; dup of one remains unknown provenance. All open provenance is
UNKNOWN: there is no readonly/default-deny permission policy in this experiment.

Clone, exec, close_range, unshare and selected alternate FD creation/transfer
interfaces return ENOSYS. Same-task nested slow calls return EDEADLK, other task
identities are refused, and no guard is held across blocking syscalls. Uncertain
close outcomes remain pending (no automatic provenance withdrawal). This is a
single-task debugging mode, not general shell/container compatibility, complete
FD interception, or an adversarial isolation boundary. Existing raw-entry/path
race limitations still apply. Do not enable it as an agent sandbox yet.

For validation only, prctl(PR_ELF_FD_QUERY=0x46445452, selector, fd) returns:

- selector 0: tracked record count;
- selector 1: descriptor generation;
- selector 2: open-description identity;
- selector 3: CLOEXEC bit.

Missing records return ENOENT. This diagnostic interface is absent from the
normal payload and exposes no permission grants. It is not a stable public ABI.

The libc-free guest runs through the actual loader/dispatcher, reads a fixture
file, checks duplication identities and descriptor flags, closes descriptors,
and checks failure and capacity behavior. It links none of the FD metadata
modules itself. Optional existing Alpine/Ubuntu fixtures also run their cat
programs; missing fixtures are reported as skipped, not counted as passes.

The runtime guest also writes/reads an anonymous memfd, duplicates it and reads
after closing the original, and exercises a nonblocking eventfd counter. Native
F_GETFD is compared with tracked CLOEXEC for both creators. Invalid flags leave
metadata unchanged; a full metadata table rejects creation before the syscall.
MFD_CLOEXEC uses bit 0, while eventfd uses O_CLOEXEC's bit. Both remain UNKNOWN
provenance; this adds metadata coverage, not permission enforcement.

The guest event-loop regression registers eventfd and timerfd with a tracked
epoll instance, checks event payloads, consumes readiness, and confirms closing
the last descriptors removes readiness and metadata. Timer expiration is tested
with a one-shot 1 ms timer and a bounded wait. CLOEXEC/non-CLOEXEC, invalid flags
or clock IDs, and capacity exhaustion are covered. epoll_ctl/epoll_pwait and
timerfd_settime retain kernel behavior; no userspace event loop is implemented.

The pipe2 adapter preflights two free slots and two generation values before
kernel entry, then records the read and write ends with distinct descriptions.
Tests cover CLOEXEC/nonblocking flags, a duplicated writer, EOF after the last
writer closes, EFAULT, invalid flags, and 0/1/2 free-slot boundaries. Failed
creation publishes no records. Reading the returned array relies on the current
single-task AArch64 mode; this is not a concurrent user-memory snapshot guarantee.

Socket coverage uses AF_UNIX stream sockets, including bidirectional socketpair
IO, duplicated endpoint lifetime, EOF, CLOEXEC/nonblocking flags, EFAULT, invalid
types, and pair capacity boundaries. Creation and IO retain host kernel behavior;
recvmmsg remains unsupported.
On this host, raw socketpair accepts unknown high type bits that socket rejects;
the invalid-type test uses type 15, which the host rejects with EINVAL.

Accept tests use an autobound abstract UNIX listener, connect without another
task, and exercise accept, accept4 with zero flags, and accept4 with CLOEXEC and
NONBLOCK. They verify peer address output, distinct descriptor identity,
bidirectional IO, EOF, empty-queue EAGAIN, invalid flags/FD, and rejection at full
capacity without consuming the queued connection (accepted after one slot frees).
The runner obtains native AArch64 accept/accept4 status flags as a reference:
this host inherits listener O_NONBLOCK even without SOCK_NONBLOCK. The adapter
preserves host behavior rather than implementing Linux flag normalization.

The separate rights guest exercises recvmsg SCM_RIGHTS: two descriptors,
MSG_CMSG_CLOEXEC, repeated MSG_PEEK against a native reference, partial/no control
space and MSG_CTRUNC, full/one-free/two-free table boundaries, and rollback when
the control buffer or msghdr output fields are read-only. A data-only receive
with no control space works at full capacity. FD numbers are checked after
rollback to detect leaked kernel descriptors, in addition to metadata counts.

This experimental recvmsg adapter snapshots the header with self process_vm_readv,
receives into a bounded private control buffer, and uses process_vm_writev for
fault-checked output. It preflights the maximum number of rights the caller's
control length could hold, so oversized control buffers can return ENOSPC even
when the queued message has few/no descriptors. It does not shrink the control
buffer silently. Each received descriptor has UNKNOWN origin and description=0;
SCM_RIGHTS does not establish sender permissions or local alias identity.
Copy-back failure closes received descriptors but may have consumed data or
partially written outputs. This adds copying/syscall overhead only to the
experimental recvmsg path; ordinary read/write remain kernel operations.

On this host only the first MSG_PEEK delivers SCM_RIGHTS; subsequent peeks and
the consuming receive return data without the rights. The native reference
records this behavior rather than assuming Linux repeated-peek semantics.
recvmmsg and other FD-bearing ancillary types are not covered by this increment.
