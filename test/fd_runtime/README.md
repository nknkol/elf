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
timerfd_create, inotify_init1, signalfd4 creation, pipe2, socket, socketpair,
accept, accept4, pidfd_open, pidfd_getfd, dup, dup3,
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
recvmmsg is covered by the bounded batch adapter described below.
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
Other FD-bearing ancillary types are not covered by the SCM_RIGHTS adapter.

The batch guest covers recvmmsg with two SCM_RIGHTS messages, CLOEXEC, a partial
batch, MSG_WAITFORONE on a blocking socket, aggregate capacity rejection without
consuming queued messages, and failure while publishing the first/second control
buffer, msg_len, or timeout. Completed-prefix descriptors stay tracked; all
unpublished suffix descriptors are closed, with FD-number reuse checked for
leaks. Native full/partial datagram batches are also checked by the runner.

The experimental adapter allows at most 8 messages per call (E2BIG above that)
and at most 128 potentially received descriptors across the vector. It snapshots
all input headers and reserves their aggregate upper bound before kernel entry;
a bad later header or insufficient aggregate capacity rejects the entire call.
It invokes native recvmmsg once with private headers, control buffers and timeout,
so waiting, MSG_WAITFORONE and partial kernel results remain kernel behavior.
Output-copy failure may occur after later messages have already been consumed;
the adapter returns the published prefix count (or the copy error if empty) and
closes unpublished descriptors. Timeout-copy failure closes all received FDs and
returns the copy error. These are explicit experimental limits, not full Linux
fault/partial-progress equivalence. Origin and alias identity remain UNKNOWN.

The notify guest validates inotify file modification/close events and signalfd
signal delivery. signalfd4(fd=-1) creates a tracked descriptor; updates of an
existing descriptor keep its generation, description and CLOEXEC untouched and
need no free slot. Tests fill the table, update the signal mask, close the original
FD and read the new signal through a duplicate. Creation flags, ignored update
flags, malformed arguments and capacity errors are checked against kernel state.
Inherited/untracked descriptors remain untracked when their mask is updated.
inotify_add_watch now enters the shared path backend and resolves absolute,
relative and bind paths, following the final symlink unless IN_DONT_FOLLOW is set.
The path suite compares native and loader outcomes, exercises actual modification
events, and rejects unmapped host-source spellings. On this host symlink watches
with IN_DONT_FOLLOW return EACCES; that rejection is preserved, not counted as a
successful symlink watch. Path resolution races and permission enforcement remain
outside this increment; FD creation coverage is not a complete isolation claim.

The range guest verifies the explicit close_range ENOSYS fallback, not range
emulation. It receives an inherited descriptor via pass_fds and creates/duplicates
others, checks they survive all tested range flags unchanged, then exercises
caller-side F_SETFD/close fallback with matching metadata. The ordinary HarmonyOS
build runs the same guest without metadata queries: native close_range is sandbox
fatal here, including empty ranges and invalid flags. Complete range emulation
must account for inherited and loader-owned descriptors and table ownership.

The pidfd guest validates pidfd_open and self-process pidfd_getfd through the real
loader. Both new descriptors have CLOEXEC set by the kernel. pidfd_getfd imports
UNKNOWN provenance and description=0, even when the sender happens to be this
process; it does not infer local alias permissions. Tests check shared kernel
file offsets, survival after the source closes, duplicated pidfd usability,
invalid handles/flags, full-table rejection and retry after releasing one slot.
This does not enforce cross-process import policy. io_uring_setup remains refused
in the experiment: a working setup call alone does not cover asynchronous FD
creation or the host's blocked io_uring_enter/register paths.

Unsupported direct FD creators now share one experimental-only routing/denial
inventory: fanotify_init, userfaultfd, perf_event_open, bpf, mq_open, open_tree,
fsopen, fsmount, fspick, open_by_handle_at, seccomp and io_uring_setup. Header-
available landlock_create_ruleset and memfd_secret are included conditionally.
The current target headers expose the first 12; the latter two were not exercised.
The independent guest list tests zero and invalid arguments through patched SVCs,
unchanged metadata, and continued supported IO. Ordinary builds are unchanged.
BPF/seccomp are denied as whole multiplexed interfaces, including their non-FD
commands; this is an explicit experimental compatibility restriction, not a
claim that the host rejects those operations. FD-producing ioctls and other
ancillary types remain outside coverage; this is not a complete syscall allowlist.

The ioctl guest checks FIOCLEX/FIONCLEX metadata synchronization with native
F_GETFD, stable generations/descriptions, and independent duplicate CLOEXEC bits.
Known records can be updated at full capacity. Updating an inherited untracked
FD reserves a slot before ioctl, returns ENOSPC without changing the kernel flag
when full, and adopts UNKNOWN identity after a slot is released. FIONBIO remains
kernel-driven and changes the shared status flags without changing metadata.
TIOCGPTPEER is explicitly ENOSYS in the experiment because it creates an FD;
a native /dev/ptmx unlock succeeded here but peer creation returned EACCES, so
success-path tracking is not claimed. Other FD-bearing ioctls remain unaudited.
