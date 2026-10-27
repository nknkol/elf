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
recvmsg/recvmmsg (including SCM_RIGHTS) remain unsupported.
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
