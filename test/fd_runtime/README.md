# Single-threaded process FD runtime experiment

Run from the repository root:

```sh
make check-fd-runtime
vendor/proot/svc/build/elfloader-proot-fd-experiment --mode compat -- /path/to/program
```

This builds a separate executable and manifest. Normal `make build`/`make check`
continue to produce `elfloader-proot` with the existing behavior. Both builds
share intermediate object paths, so do not build them concurrently. The last
build also determines `src/elfloader`; prefer the named snapshots above.

The experimental payload initializes a private registry on first slow call or fork,
tracks up to 128 descriptors from openat, memfd_create, eventfd2, epoll_create1,
timerfd_create, inotify_init1, signalfd4 creation, pipe2, socket, socketpair,
accept, accept4, pidfd_open, pidfd_getfd, dup, dup3,
F_DUPFD/F_DUPFD_CLOEXEC and
F_SETFD, and routes close through reserved outcome bookkeeping. Inherited FDs
start untracked; dup of one remains unknown provenance. All open provenance is
UNKNOWN: there is no readonly/default-deny permission policy in this experiment.

General shared-VM/shared-FD clone (except bounded vfork below), close_range, unshare and selected alternate FD creation/transfer
interfaces return ENOSYS. Same-task nested slow calls return EDEADLK, other task
identities are refused, and no metadata mutex is held across blocking syscalls. Uncertain
close outcomes remain pending (no automatic provenance withdrawal). This is a
single-threaded process debugging mode, not general shell/container compatibility, complete
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

Single-task exec/execveat now chain through the experimental loader with a sealed
memfd snapshot of non-CLOEXEC records. The new payload restores generations and
known duplicate identities, verifies each inherited FD with F_GETFD, and closes
the transport. Imported origins are downgraded to UNKNOWN: sealing validates
immutability, not authority. Initialization failure remains sticky rather than
silently starting an empty table. The internal --fd-state option requires
--child-loader and exists only in experimental builds; it is not an authenticated
protocol. Loader and payload must be built together with FD_EXPERIMENT.

The exec guest uses a private loader copy to force a real kernel exec failure
after snapshot creation, checks unchanged metadata/flags and transport cleanup,
then performs exec and execveat through two image replacements. Tests verify
non-CLOEXEC identity, removal of CLOEXEC records (including ioctl-set flags),
shared kernel offset and preserved root/bind view. An unsealed handoff is rejected
persistently. Optional Alpine busybox sh and Ubuntu dash each run an exec builtin
into cat. General shared-VM clone/threads, general shell compatibility and permission enforcement
remain unsupported; existing bounded exec/shebang/empty-path limits still apply.

Exec restore boundary fixtures now include sealed snapshots naming an absent FD,
the transport FD itself, or an invalid CLOEXEC entry. Each produces a persistent
initialization error. A valid sealed snapshot with serial UINT64_MAX verifies
that F_SETFD/FIOCLEX/FIONCLEX still update existing records without allocating a
new generation, while new FD assignments return EOVERFLOW; close still works.
These synthetic snapshots exercise metadata validation, not protocol authenticity.

Private fork now uses the generated clone notification gate: SIGCHLD with optional
CLONE_CHILD_SETTID/CLONE_CHILD_CLEARTID is accepted, while other clone combinations
remain ENOSYS. Before kernel entry the parent acquires the active-call reentry
slot, initializes/drains metadata and rejects pending close outcomes. It releases
that shared slot only on the parent's return; the child never releases it. Each
child rebinds its copied singleton registry to its own TID without changing its
copied records. The payload mappings are private: this is not the shared-registry
thread path, nor permission to use CLONE_FILES based on Linux assumptions.

The fork guest covers clone as the first instrumented operation, child TID output,
parent/child CLOEXEC independence, child close versus parent survival, and child
exec with preserved records. Direct slow-entry clone stays rejected; the generated
original-stack clone gate is required. A parent dying before its return can strand
an active-call slot; automatic reclamation of that slot is not implemented.

Real shell workflow coverage (`python3 test/fd_runtime/shell.py`) checks
Alpine busybox and Ubuntu dash pipelines with external cat, subshells, background
exit/wait status, command substitution, and FD redirection across fork. It binds
host /dev/null explicitly: extracted minirootfs fixtures lack the device, causing
background jobs to fail independently of clone support. Both now also pass an
external command followed by a builtin (dash's vfork route). Missing optional
rootfs fixtures are reported as SKIP.

Bounded vfork now accepts exactly CLONE_VM | CLONE_VFORK | SIGCHLD (0x4111).
The kernel still supplies shared memory and parent suspension; flags are never
rewritten into fork. Before clone, the parent copies records into a separate
child arena and repairs its internal pointers. Child operations select that
arena by TID; the parent's arena stays untouched. Parent kernel return after
child exec/exit discards the child state and unmaps exec scratch retained in the
old shared VM. A dedicated child reentry slot is retired at the same boundary.
Failed exec cleans up normally and can be retried. Nested clone (including private fork),
CLONE_FILES, extra vfork flags and ordinary shared-VM threads remain unsupported.
This is FD metadata support, not a claim that all legacy backend globals or
arbitrary shared-VM guest operations are isolated. The child's guard slot is now
reclaimed even when a slow call never returns.
Path/exec scratch uses parent reservations as described below; other internal
temporary mappings interrupted by death still need separate accounting;
parent death before its clone return is also not reclaimed automatically.

The libc-free vfork guest runs both natively and through the loader. It checks
shared memory visible immediately on parent return, independent kernel CLOEXEC,
child dup/close with unchanged parent records, first-call initialization, exit,
SIGKILL outside a slow call, failed exec then successful exec, nested clone
rejection, and 40 exec cycles (more than the 32 active-call slots). The real dash
workflow additionally covers its same-stack libc vfork calling convention.

The interruption regression adds 40 vfork children blocked in recvmsg on empty
socketpairs, each terminated by default SIGALRM. Native and loader runs must both
observe signal 14, and the parent must retain its FD generation/CLOEXEC and remain
able to enter slow calls after every child. This failed on the previous backend
as abandoned calls exhausted the 32-slot shared pool. The child now uses a
private-payload dedicated guard slot for its entire vfork lifetime, including
acquisition/return interruption windows. Only the suspended parent's kernel
return authorizes retirement; no reusable public slot is reclaimed by TID.
The guard test also fills the public pool and verifies child-slot retirement
leaves all 32 owners intact. This does not implement general dead-task reaping.

Path and exec scratch are now reserved by the parent before kernel vfork entry,
using the actual sizes of Bridge and ExecScratch. The child borrows zeroed slots
(best-fit so exec leaves room for nested path resolution), and normal free only
returns a slot. Kernel vfork return discards both mappings, including clone
failure. Partial reservation failure frees earlier reservations before returning
an error. This removes the child's mmap-to-registration and munmap-to-forgetting
interruption windows for these two adapters. Non-vfork and normal builds retain
per-call kernel mmap/munmap; other internal mappings are not covered.

The guest adds 32 interrupted FIFO openat cycles and checks parent virtual pages
via numeric /proc/<pid>/statm after every child, as well as unchanged FD metadata.
Numeric PID avoids the unsupported /proc/self magic-link resolver route. The
runner creates the FIFO in the HarmonyOS app cache (ordinary temp directory on
other hosts), because workspace storage rejects FIFO creation, and links it into
the temporary working directory. Both the FIFO and its directory are cleaned up.
The existing failed-exec/retry and 40 successful exec cycles exercise nested
scratch use and reuse alongside the new interrupted path test.

Private fork children now switch to a guard slot in their own private payload
mapping before returning to guest code. An interrupted slow call or successful
exec can abandon that slot: the kernel frees the old VM without consuming an
ancestor's shared-pool capacity. A nested private fork resets only the child's
copied slot; the parent retains its active clone lease until its own return.
The vfork-specific slot still takes priority while that child shares the VM.
The initial experimental task also binds privately as described below; the normal
build and general shared-VM/thread guard retain their shared-pool behavior.
Parent-only clone cookies may reference inherited private slots; child finish
and transaction cleanup must never dereference those leases.

The fork guest checks nested fork, 40 successful child execs, and 40 children
terminated by SIGALRM during blocking recvmsg. Parent FD metadata and CLOEXEC
survive every round. The interrupted test failed on the old shared-slot path.
A guard ownership test also leaves a child's private slot active at exit and
verifies the parent's active slot remains held and reusable after release.
This avoids ordinary fork-child guard leakage rather than adding TID-based
reaping. Interrupted clone notification transactions and arbitrary parent-death
handling are still separate work.

The experimental initial task now binds its private reentry slot at the first
entry, before any lease is acquired. This removes the remaining shared guard
pool from the experimental runtime, including initial-process exit/exec. A
foreign TID in the same VM receives EOPNOTSUPP unless it is the explicitly bound
vfork child. The ordinary build keeps the existing shared guard implementation.
Binding is performed at entry rather than inside dispatch so a nested signal
cannot bypass an already-held lease. The dedicated test requires no mmap calls,
checks recursion and foreign-TID rejection, and preserves the parent's held
lease while retiring an abandoned vfork child lease.

The orphan guest creates an 80-generation chain whose parents exit without
waiting. Every descendant verifies inherited FD metadata and can fork again,
exceeding the notification pool's 64 slots cumulatively. A supervising subreaper
checks the final child's completion and reaps all 81 processes. This exercises
parent exit after normal clone return; it does not force death inside the clone
callback or prove recovery of unknown-child/INIT/finalizer-abandoned transactions.
Those conservative notification limits and non-guard resource cleanup remain.

`files.py` exercises optional Alpine/Ubuntu rootfs ls, copy/rename, symlink
readback/canonicalization, find, tar creation and listing, plus Alpine tar
extraction (13 passing workflows). Ubuntu GNU tar extraction requests openat2
RESOLVE_BENEATH and is reported as KNOWN LIMIT with exit 2/ENOSYS. Its request is
not silently downgraded to openat. A separate runtime probe checks the new
fchmodat2(452) fatal-syscall guard: old host headers omitted it, while guest glibc
emits it for flagged fchmodat. HarmonyOS now returns ENOSYS instead of allowing
SIGSYS. This is an unsupported-call fallback, not fchmodat2 emulation.

`beneath.c` exercises the experimental openat2 single-component O_PATH |
O_NOFOLLOW + RESOLVE_BENEATH subset through real patched SVCs: explicit dirfd,
AT_FDCWD, CLOEXEC/accounting, rejected escapes and multi-component names,
symlink identity, missing/non-directory targets, and configured bind crossings.
Explicit O_DIRECTORY allows trailing separators on a single directory component;
symlink following remains unsupported. Both Alpine and Ubuntu pass shallow and
nested tar extraction, with extracted contents verified on the host. This does
not imply general multi-component openat2 support.
