# Agent filesystem profiles (planning prototype)

The primary product direction is an agent filesystem sandbox using existing
system/brew tools. A separate Linux rootfs is a secondary mode. This repository
contains the ELF execution backend and vendored PRoot path semantics together;
bubblewrap is not a build or runtime dependency.

`plan.py` validates and prints a filesystem plan only; its output is marked
`not-connected`. `launch.py` connects the same plan to the FD-experiment
backend's file access guard (see "Launching an agent" below). Do not pass the
plan to the legacy bind CLI expecting readonly or default-deny isolation.

From the repository root, with real absolute paths:

```sh
python3 tools/agent_sandbox/plan.py profiles/agent.json \
  --brew-prefix /path/to/brew \
  --workspace /path/to/project \
  --state /path/to/private-run
python3 -m unittest discover -s test/agent_sandbox -v
```

The profile exposes the brew prefix at its original guest pathname (readonly),
the workspace at `/workspace` (read/write), and private home/tmp/cache backing
directories. Unknown paths default to deny. Explicit nested mappings use the
longest component prefix. Symlinks must be resolved by the runtime before policy
checking; the Python access model operates only on canonical guest paths.
Private state must be outside exposed source trees. Planning resolves existing
host symlinks and compares device/inode identities against existing ancestors
to reject case aliases, including missing state tails. Inspection errors reject
the plan; distinct case-sensitive names remain distinct. This read-only snapshot
does not guarantee safety against later pathname races or all bind-mount aliases.

Add platform system libraries/interpreters/resources explicitly to `mounts`
with `access: ro`. The sample is a policy example, not a complete tested brew
runtime profile. The complete brew prefix is exposed so Cellar/opt links and
resources can remain usable; dependencies outside that prefix still need rules.
Environment expansion and shell execution are not used. Only whole-path
`${BREW_PREFIX}` and `${WORKSPACE}` substitutions are supported.

Implementation status of the original steps: policy transport across exec,
path/FD mutation and read guards, listing filters and ancestor traversal are
implemented in the FD experiment, and `launch.py` creates private state and a
clean environment. Remaining: validate real brew programs and platform
libraries in the HarmonyOS sandbox, and close known interception bypasses
before claiming hostile-agent isolation.

## Launching an agent

```sh
make check-fd-runtime   # or: python3 vendor/proot/svc/build_elf.py --fd-experiment
python3 tools/agent_sandbox/launch.py profiles/agent.json \
  --brew-prefix /path/to/brew --workspace /path/to/project \
  --state /path/to/private-run -- /bin/sh -l
```

The launcher compiles the profile, creates the private directories (0700) and
`<state>/root`, a root that contains only mountpoint placeholders. That root is
the denied mount, so guests can traverse and list exactly the exposed
mountpoint names, and an ancestor stat reports these placeholders rather than
host directories. It is recreated on every launch; an existing `root` without
the launcher's marker is refused, never deleted. Private home/tmp/cache persist.

Every mount becomes a loader volume with its ro/rw access, behind deny for the
root: `--guard-file-access` plus `--allow-stdio-output`, `--allow-pipe-output`,
`--allow-stream-input` and `--revalidate-file-fds`. The loader and the static
exec helper must match the FD build manifest. The helper enters the guest
working directory (`--cwd`, default the rw workspace target) and execs the
command through the payload, so the command path, shebang and dynamic linker
use the same policy as later execs and must be visible. The guest environment
is clean: HOME, PATH (exposed ro `bin`/`sbin` first), USER, LOGNAME, SHELL,
LANG, TMPDIR/XDG_CACHE_HOME for private tmp/cache, the host TERM, and explicit
`--env KEY=VALUE`; no other host variable is passed. `--print` shows the
launch as JSON without creating state.

Backend limits are checked before launch: at most 8 mounts (private ones
included), 16 environment entries, 255-byte paths/entries, no ":" in paths.
The command needs an absolute guest path. Profiles must expose the platform
programs, libraries and the dynamic linker's guest path (on merged-usr systems
`/lib` is a symlink to expose explicitly). This is the experimental file access
mode, not hostile-code isolation; see the known gaps above and docs/STATUS.md.

For the functioning experimental path backend and its tests, see
[vendor/proot/SVC_PORT.md](../../vendor/proot/SVC_PORT.md).

## Observe backing storage before selecting it

```sh
python3 tools/agent_sandbox/probe_storage.py \
  /storage/Users/currentUser /tmp /data/storage/el2/base/files
```

This explicitly writes a private temporary subdirectory inside each existing
argument, probes ASCII case lookup and hardlinks, then removes its own files.
It does not create missing target directories, traverse entire trees, modify
existing files, or run automatically while compiling a profile. Output is JSON,
marked `enforcement: not-connected`. `denied` hardlinks are a valid observation;
unknown/inconsistent results or incomplete cleanup cause a nonzero exit. Cleanup
failure reports the remaining temporary path rather than pretending it vanished.

Results are directory- and credential-specific. The application sandbox path
names the current application's backing, not a universal shared location. ASCII
case results do not establish Unicode folding/normalization rules, nor the
behavior of nested mounts. Probe each chosen backing separately; no persistent
capability cache or automatic policy decision is implemented.

Current terminal observations: home is ASCII case-insensitive; /tmp and the
application files directory are sensitive. Hardlinks are denied in all three.
Choose sensitive persistent storage for Linux rootfs names; /tmp is temporary.
Do not repair policy matching by lowercasing paths or emulate linkat with copies.
The planner's `access_for` remains only a string model: case variants are not
covered by a runtime permission guarantee. See [storage observations](../../docs/STORAGE_CAPABILITIES.md).

## Native permission decision core

`src/payload/logic/fs_policy.c` supplies a standalone allocation-free decision
core, tested by `python3 test/fs_policy/run.py` and included in `make check`.
An immutable permission array has exactly one entry per mount (root at 0,
then PRoot binding index + 1). It can represent deny, readonly and read/write.
Path callers must resolve symlinks and select the final mount first; descriptor
callers must retain trusted provenance from the same policy incarnation.
Unknown provenance is denied, regardless of the supplied numeric mount ID.
Denied access returns EACCES; mutation on readonly returns EROFS. Rename/link
require both operands writable and the same virtual mount, otherwise EXDEV.
Nested and duplicate destination selection reuses the existing PRoot table.

The FD experiment links this core for diagnostics and the opt-in path mutation
guard described below. Selected FD mutations can also be guarded in the file-mutation mode below.
No new sandbox CLI or runtime permission guarantee is introduced. Integration
still needs policy transport across loader/exec, trusted mount observations,
syscall-specific read/mutation classification (including open flags), complete
FD write/mmap coverage, and safe pathname resolution. Directory visibility and
ancestor traversal are separate from this mount-level decision.

## Experimental policy transport (observation only)

The FD build accepts `--observe-mount-access drw`: one character for root,
followed by one per configured bind in insertion order (`d` deny, `r` readonly,
`w` read/write). Length must match the final bind count plus one, up to nine
characters; malformed, empty and duplicate options fail before guest startup.
The ordinary build has no such option. Omission keeps legacy behavior.

The vector is copied into payload configuration and forwarded on each chained
exec. Diagnostic `prctl(PR_ELF_FD_QUERY, 6, mount_id, operation)` evaluates the
standalone core (`operation=0` observe, `1` mutate); it returns ENODATA if no
vector was supplied. This does not change open/write behavior or existing FD
origin tags. It is an explicitly unauthenticated observation protocol, not a
secure policy handoff: a guest can invoke the loader with different arguments.
The JSON planner is still not connected to launch.

The experimental payload ABI is now 10 (normal PRoot remains 3); older custom
payload layouts are rejected. Build and test with `make check-fd-runtime`;
its new `test/fs_policy/transport.py` runs real patched SVC calls, checks two
successive execs with/without a vector, rejects invalid input, and verifies ABI
mismatch rejection. Run it immediately after an experimental build because its
custom-payload fixture uses the most recently built `src/payload/payload.bin`.

## Partial path mutation guard

`--guard-path-mutations drw` enables a separate experiment using the same root /
bind permission vector; it is mutually exclusive with `--observe-mount-access`.
It survives chained exec and checks the resolved final mount immediately before
supported PRoot pathname operations reach the kernel. Unknown relative cwd or
dirfd provenance returns EACCES; chdir to an absolute guest path or a fresh
absolute directory open can establish a new observation. Exec-imported directory
FDs deliberately remain unknown. No implicit lowercase matching is introduced.

Covered operations: write-access/create/truncate/tmpfile openat, mkdirat,
mknodat, unlinkat, symlinkat destination, both renameat/renameat2/linkat operands,
truncate, and pathname forms of fchmodat/fchownat/utimensat. O_PATH ignores the
ordinary write/create/truncate flags. Final symlinks obey each operation's
follow/no-follow semantics. Existing cross-mount EXDEV and mountpoint EBUSY
checks remain. The narrow supported openat2 is O_PATH-only and cannot write.

This is **path mutation protection only**, not full readonly/default-deny
isolation. Reads remain allowed even for `d`; the flag does not check descriptor
writes, writable mappings, FD metadata operations/empty-path forms, or the
unmigrated xattr and socket handlers. The existing pathname race, case-alias,
raw-entry and unauthenticated loader/exec limitations remain. FD access tags
still describe the legacy mapping observation, not a grant from this vector.
The ordinary build and observation mode do not enable these checks.

`test/fs_policy/path_mutations.py` runs real SVC probes, checks readonly errors,
writable success, both rename/link ends, symlink/nested mapping selection,
cwd/dirfd origins and exec-import downgrade, then verifies host file contents,
metadata and directory entries. It also proves observation and legacy modes
still allow a write-access open. It is included in `make check-fd-runtime`.

## Partial file mutation guard (path + FD)

`--guard-file-mutations drw` includes the path guard and checks tracked FD
origins against the same root/bind vector. It is mutually exclusive with the
other two policy options and survives exec. Supported FD operations are write,
writev, pwrite64, pwritev/pwritev2, ftruncate, fallocate, fchmod/fchown,
fsetxattr/fremovexattr, utimensat with a null path, and fchownat with an empty
path plus AT_EMPTY_PATH. Transfers check the output FD: sendfile/vmsplice arg0,
tee arg1, copy_file_range/splice arg2. The kernel still performs all actual IO;
the guard adds a bounded metadata lookup and permission decision without path
resolution, allocation, or extra syscalls.

Unknown origins return EACCES; readonly origins return EROFS. The guard runs
before kernel validation, so these errors can precede EBADF or other native
argument errors. Dup and private fork preserve known origins; exec imports
still downgrade to unknown. A fresh absolute open can establish new provenance.
FD access tags remain mapping observations; the permission vector is consulted
separately on every guarded operation.

Without the explicit stdio option below, inherited stdout/stderr remain
unknown. Imported aliases and sockets receive no implicit output grant.
New pipe write ends require the separate option described below. The regression uses exit
status and host-side file checks, including readonly content/metadata integrity,
writable output, dup/fork/slot reuse and rejection of exec-imported FDs.

This is still not a readonly sandbox: arbitrary ioctl, async IO,
unmigrated pathname handlers, read visibility, policy handoff authentication and
path/alias races are outstanding. Existing mappings are not revoked. The
observation and path-only modes retain their previous behavior. ABI 6 prevents
an older custom payload from silently treating file protection as path-only.
`test/fs_policy/fd_mutations.py` is included in `make check-fd-runtime`.

## Mapping writeback guard

The file-mutation mode now also gates guest mmap/mprotect and MADV_REMOVE.
All non-private file mappings (MAP_SHARED and MAP_SHARED_VALIDATE) require a
known writable mount, even when initially read-only. This is deliberately
stricter than native Linux, and prevents a later mprotect from introducing an
unchecked file writer. Private COW and anonymous mappings remain available.
Shared executable file mmap is EOPNOTSUPP because the legacy executable-file
fallback copies into anonymous memory and cannot preserve shared semantics.

A fixed 128-interval admission table records successfully created guest
mappings, coalescing adjacent ranges. It stores addresses only, independent of
FD closure/reuse. Page rounding uses AT_PAGESZ from guest auxv. Adding write or
execute permission via mprotect, or requesting MADV_REMOVE, requires complete
coverage by admitted intervals. Executable upgrades need coverage because the
hook engine patches instructions. Initial loader/stack mappings are not
implicitly admitted; existing permissions are not revoked.

Successful munmap removes/splits coverage; failed mapping operations leave it
unchanged. Capacity is reserved before mmap or a splitting munmap, returning
ENOSPC conservatively when necessary. Successful mremap currently discards all
admissions instead of guessing new aliases/ranges, so later upgrades require
fresh admitted mappings. Private fork copies the table; guarded VM operations
in the shared-VM vfork window are EOPNOTSUPP until shared accounting exists.
pkey_mprotect is routed and returns ENOSYS in this mode. Exec begins with an
empty admission table and imported FDs still have unknown origins.

ABI 7 rejects older payloads without these checks. `vm_model.py` tests merging,
holes and atomic capacity failures against a reference bitmap; `mappings.py`
uses real SVC calls to test COW versus shared writeback, upgrades after closing
the FD, partial unmap/fixed replacement, failed operations, fork, conservative
remap invalidation and exec. No per-byte interception or file content copy is
added by the admission checks. Read visibility, general stream grants, ioctl/async IO,
initial mappings and trusted policy handoff remain outside complete isolation.

## Explicit standard output authorization

Combine `--allow-stdio-output` with `--guard-file-mutations` to let a guest use
inherited stdout/stderr when they are writable pipes/FIFOs or verified TTYs.
The option is rejected outside file-mutation mode and is preserved across exec.
At runtime initialization, kernel fstat identifies the object type; character
devices additionally need a successful TCGETS. F_GETFL excludes O_PATH and
read-only ends. Regular files, sockets and non-TTY devices (including /dev/null)
receive no output grant. Closed or ineligible descriptors simply stay unknown.
Stdin reads retain the existing behavior; no read-visibility policy is added.

The two output grants use fresh local open-description IDs, not permanently
privileged FD numbers. They permit **write/writev only**, including tracked dup
aliases and private-fork descendants. Replacing or closing/reusing fd 1/2 cannot
transfer an old grant to a file. Metadata modifications and file shared mmap
still require mount provenance. Checks after initialization use metadata only;
no fstat/ioctl is added to each write.

Grants are not serialized. After exec, all restored origins are downgraded and
only the actual fd 1/2 objects are revalidated, assigning IDs newer than the
snapshot serial. An inherited alias at another number stays unknown even if it
used to duplicate stdout. A regular file redirected to stdout receives no
stdio grant, including across exec. This does not authenticate the existing
loader CLI/policy handoff or restrict loader-internal diagnostic output.
ABI 8 distinguishes the new configuration layout from older custom payloads.

`test/fs_policy/stdio.py` covers pipe/PTY output, stdin, writev, dup/fork/exec,
FD reuse, regular-file/socket/non-TTY rejection and invalid options. Available
Alpine and Ubuntu fixtures also run a protected shell read/printf followed by
exec→cat. Local pipes are covered by the next option; socket authorization and
authenticated preservation of other inherited FDs remain work.

## Locally created pipe output

`--allow-pipe-output` requires file-mutation mode and authorizes the write end
of each successful guest pipe2. It is independent of `--allow-stdio-output`;
use both for shell pipelines. Read ends, socketpair, inherited pipe aliases and
ordinary files receive no new grant. A local per-record capability follows
tracked dup/fcntl duplication and private fork, and is cleared by replacement,
close/reuse and exec. It does not grant mount identity or metadata/mmap access.

Allowed output operations are write/writev, sendfile, splice, tee, vmsplice and
copy_file_range; the kernel retains its native validation (e.g. copy_file_range
normally rejects pipe output). Pwrite and metadata operations do not receive a
pipe exception. No extra syscall or content copying is added to the write path.
The capability is deliberately absent from the exec snapshot format: import
cannot assert it. After exec, only actual stdout/stderr may be revalidated by
the separate stdio option; other inherited pipe aliases remain unknown.

ABI 9 covers the new configuration and capability semantics. Model tests check
dup/fork, CLOEXEC, slot replacement and snapshot dropping; `pipes.py` exercises
real pipe IO and transfers, metadata denial, socket/regular-file rejection and
exec downgrade. Available Alpine/Ubuntu fixtures run protected three-stage
pipelines, command substitution and subshell output. These tests use captured
pipe stdout. Regular-file output redirection uses the separate option below.

## Revalidating regular files after exec

`--revalidate-file-fds` requires `--guard-file-mutations`. It re-derives the
current mount view of regular files listed in an imported FD snapshot. It never
accepts the snapshot's claimed mount or access permission, and does not adopt
arbitrary FDs inherited at initial launch. Without this option, exec continues
to downgrade file origins to unknown. Experimental ABI 10 carries this option.

At restore time, fstat and /proc/self/fd identify the live file; a no-follow
stat of the reported path must match its device and inode. Reverse and forward
mapping must identify exactly one effective mount view, followed by a second
FD identity check. Deleted/replaced files, paths outside the mount table,
nonregular objects and ambiguous aliases remain unknown. Multiple views are
rejected even if all are writable; a host root of `/` overlapping bind sources
can therefore prevent revalidation. The current mount policy still determines
whether writes return success, EROFS or EACCES.

This is fresh authorization under the current configuration, not proof of the
original view or authenticated exec transport. The pathname checks are not
race-free. Checks run only at restore; ordinary writes retain table lookups and
native kernel IO. Default-deny read visibility and other permission gaps remain,
so this does not establish complete hostile-agent isolation.

`revalidate.py` covers two consecutive execs, forged sealed snapshots claiming
writable origins for read-only/denied files, disabled-option behavior, outside
files, ambiguous aliases and unlinked/replaced files. Available Alpine/Ubuntu
fixtures verify shell pipeline redirection and append through exec.


## Pathname extended attributes

The PRoot bridge maps set/get/list/remove xattr and their `l*` pathname forms.
Ordinary forms follow the final symlink; `l*` forms operate on the link itself.
Both mutation-guard modes apply mount policy to set/remove operations, including
known cwd-relative paths and nested binds. An unknown relative cwd cannot grant
mutation rights. Names, values, sizes and flags retain the native syscall ABI;
FD forms retain the existing descriptor handling. No content VFS or new slow
syscall selection is introduced.

`test/fs_policy/xattrs.py` checks real xattr IO and host state in both guard
modes, observation mode and unguarded FD mode; `--normal` checks the default
build. It requires native xattr support on the fixture backing and fails clearly
if that prerequisite is unavailable. The native capability probe runs in a
separate child. Tests include symlink follow/no-follow, dangling links, nested
mounts, cwd provenance, create/replace/remove and size queries/short buffers.
Read visibility is still not default-deny. ACL/security attribute semantics are
left to the host, newer xattrat interfaces are not added, and pathname races
remain outside this increment's guarantee.


## Bounded ioctl support in file-mutation mode

`--guard-file-mutations` now rejects unclassified ioctl commands with
EOPNOTSUPP. Neither the command's `_IOC_READ` nor `_IOC_WRITE` encoding is an
access-policy declaration: it describes argument copying, not effects.

| Requests | Admission |
| --- | --- |
| FIOCLEX/FIONCLEX/FIONBIO | Generic FD/status controls; existing CLOEXEC tracking remains active |
| FS_IOC_GETFLAGS/GETVERSION/FSGETXATTR | Regular file or directory, native result |
| FS_IOC_SETFLAGS/SETVERSION/FSSETXATTR | Known writable mount, then regular-file/directory type check; native permissions still apply |
| FIONREAD | Regular file, FIFO/pipe, socket, or character FD with successful TCGETS |
| TCGETS/TIOCGWINSZ/TIOCGPGRP | Character FD with successful native TCGETS |
| TIOCGPTPEER | Existing ENOSYS contract: unsupported FD creation |
| All others, including FICLONE/FICLONERANGE/FIDEDUPERANGE, TIOCSTI and TCSETS | EOPNOTSUPP; embedded-FD and terminal/device mutation semantics are not implemented |

Known filesystem setters return EROFS for readonly sources and EACCES for
unknown/denied sources before reading their argument. Pipe/stdio output grants
do not grant filesystem setter rights. Queries still do not enforce default-deny
read visibility. Type probing adds fstat (and TCGETS for terminal queries) only
to the admitted ioctl path, not ordinary read/write. The existing supported-task
and FD race limitations remain; this is not a complete device security model.

Observation, path-only and unguarded modes retain their prior ioctl behavior.
`test/fs_policy/ioctls.py` checks an isolated native baseline, real reversible
NODUMP changes on private files, protected-file ctime/content, dup/replacement,
pipe controls, CLOEXEC, unknown/read-encoded commands, clone/dedupe rejection,
and real PTY queries/injection rejection. It requires PTY support for its terminal
case. Full interactive-terminal settings and broader device compatibility are
not claimed by this limited query support.


## fcntl command boundary

The FD experiment normalizes fcntl's command to the kernel's unsigned 32-bit
ABI before both policy checks and descriptor bookkeeping. High nonzero register
bits must not hide F_DUPFD/F_DUPFD_CLOEXEC or F_SETFD effects. This correction
applies to all FD experimental modes, not just file-mutation mode.

In `--guard-file-mutations`, only these command families are admitted:

| Commands | Policy |
| --- | --- |
| DUPFD/DUPFD_CLOEXEC, GETFD/SETFD, GETFL | Existing descriptor tracking and native validation |
| SETFL | Native flags/access-mode semantics, except O_ASYNC requests return EOPNOTSUPP |
| GETOWN/GETOWN_EX/GETSIG/GETLEASE/GET_SEALS | Native queries; no default-deny read claim |
| GETPIPE_SZ/SETPIPE_SZ | Native pipe validation and resource limits |
| GET_RW_HINT/GET_FILE_RW_HINT | Native queries |
| GETLK/SETLK/SETLKW and OFD equivalents | Known non-denied mount source, then native lock and access-mode validation |
| SET_RW_HINT/SET_FILE_RW_HINT | Known writable source, then native behavior |
| Everything else | EOPNOTSUPP, including owner/signal/lease/notification setters, ADD_SEALS and unknown commands |

Advisory locking is not file-content modification: a known readonly file can
hold a native read lock. Locks cannot grant read/write access. Denied and unknown
sources return EACCES for the listed lock operations; hint setters return EROFS
for readonly and EACCES for denied/unknown sources. No guest flock pointer is
parsed by the policy check. Rejected commands cannot dereference their argument
or alter kernel state through this dispatcher. The check adds no allocation or
host lookup to fcntl; ordinary IO remains unchanged.

Guest ADD_SEALS is deliberately unsupported here until private/imported memfd
capabilities can be distinguished. Internal exec handoff still uses its own raw
sealing path; that does not authenticate guest-supplied snapshots. Other modes
retain native command behavior. This is a bounded command policy, not complete
read isolation, cross-process locking isolation or shared-FD race protection.

`test/fs_policy/fcntls.py` compares real SVC results with isolated native runs,
including host-held POSIX lock contention seen by both POSIX and OFD guest locks.
It checks high-bit duplicate/setfd bookkeeping, shared status flags, inability
to turn O_RDONLY into O_RDWR, pipe capacity controls, readonly/unknown/denied
policy, unsupported commands, unchanged protected file content/ctime, and all
four experimental modes. Native hint setters on the current backing return
EOPNOTSUPP; comparison is error parity, not proof of successful hint support.


## madvise argument-width regression

Experimental dispatch normalizes madvise advice to the kernel's signed 32-bit
argument before selecting the MADV_REMOVE mapping guard. This closes a reproduced
bypass where high register bits hid MADV_REMOVE from the guard while the kernel
still punched a hole in a live shared mapping after mremap had cleared admissions.
The regression uses a private writable fixture; it does not claim a demonstrated
readonly-mount escape. No extra path lookup, syscall or ABI layout is introduced.

`test/fs_policy/madvise_abi.py` tests low bits, bit 32 set, and all high 32 bits
set, in native, unguarded, observation, path-only and file-mutation modes. It
verifies actual file zeroing in native/compatibility modes and EACCES with
unchanged bytes/size/mtime/ctime in protected mode. MADV_NORMAL and invalid
negative advice retain their native behavior. Other mapping/admission and
executable-code limitations remain as documented above.


## Asynchronous IO is unsupported in file-mutation mode

`--guard-file-mutations` returns ENOSYS for io_setup, io_destroy, io_submit,
io_cancel, io_getevents, io_pgetevents, io_uring_setup, io_uring_enter and
io_uring_register before accessing request structures or entering the kernel.
This is unconditional in protected mode, including operations that purport to
use an existing context/ring. Slow routing alone did not authorize IOCB file
access: a reproduced PWRITE request changed a private readonly-bind fixture
through an inherited writable FD whose ordinary write was rejected.

This closes those syscall submission/control entries; it does not implement
asynchronous IO, authenticate inherited resources, revoke previously submitted
external IO, or establish complete hostile-code isolation. Other experimental
modes retain their previous Linux AIO behavior and existing io_uring restrictions.
No new configuration layout or slow-path selection is introduced.

`test/fs_policy/async_io.py` uses isolated native AIO as a capability/control run,
verifies compatibility modes when native PWRITE completes, and always tests the
nine protected entries with valid structures and invalid/empty arguments. Host
content/size/mtime/ctime must remain unchanged. Native capability unavailability
is reported separately and never skips the mandatory protected-mode checks.


This is an asynchronous-interface support limit, not a network isolation policy.
io_uring can also carry network requests; rejecting it may require applications
to fall back to synchronous/socket APIs. In the current HarmonyOS FD experiment,
setup was already unsupported and enter/register already returned ENOSYS. This
change adds no address, protocol, endpoint or Internet-access filtering. Local
AF_UNIX FD-transfer/lifecycle tests validate file capability transport, not a
network sandbox. A system security notification must be diagnosed separately;
a passing local regression does not identify its source.


## Write-access preflight follows mutation policy

Development purpose: this is a userspace filesystem sandbox running inside the
existing system sandbox, not a system-sandbox escape or privilege-escalation
tool. The regression uses private temporary files and preserves host denials.

Path queries through faccessat/faccessat2 with W_OK now consult the same selected
mount mutation policy as actual writes. Readonly paths return EROFS, denied or
unknown relative origins return EACCES. Resolution follows the final symlink
unless AT_SYMLINK_NOFOLLOW is requested. Known cwd/dirfd and nested mounts retain
their selected view. Mode and faccessat2 flags use their native 32-bit ABI;
invalid mode/flag bits are rejected before policy evaluation.

In file-mutation mode, faccessat2(W_OK, AT_EMPTY_PATH) additionally checks the
tracked FD origin, or cwd origin for AT_FDCWD. Path-only mode does not authorize
empty-path FD operations. If policy allows the query, the host still decides
its result; a writable view does not promise that the host supports the query
or permits writing. F_OK/R_OK/X_OK without W_OK retain existing behavior, so
this is not default-deny visibility or a race-free guarantee of a later write.

`test/fs_policy/access.py` checks all four experimental modes; `--normal` checks
the default build. Cases cover high parameter bits, invalid modes/flags, nested
binds, following/nonfollowing symlinks, cwd/dirfd paths, inherited FDs and empty
paths. Host contents/mode/size/mtime/ctime must remain unchanged. Native controls
on the actual fixture backing currently return EACCES for W_OK on its symlink
and EINVAL for AT_EMPTY_PATH queries. These restrictions are retained, not
emulated away or counted as successful empty-path compatibility.


## Default-deny reads and directory visibility (file access mode)

`--guard-file-access drw` includes every `--guard-file-mutations` check and
adds read and visibility checks. A path in a deny mount is hidden unless it is
a strict ancestor of an effective non-deny bind; such ancestors are traversal
only. PRoot resolution classifies every component, relative base and symlink
referee before the host sees it, so a hidden name returns EACCES whether or not
it exists, and neither a symlink nor `..` can route through it. Ancestors allow
stat/statx/statfs, non-write access checks, chdir/fchdir, read-only
`O_DIRECTORY` or `O_PATH` opens and listing; content, links, xattrs, watches and
exec are refused. getdents64 reads into a private payload buffer and copies
only visible records to the guest, so hidden names never appear in guest
memory, not even transiently or past the returned length. Batches that are
entirely hidden are retried so that zero still means end of directory.
inotify watches on a visible directory with a hidden direct child bind are
refused with EACCES, because events would name that child; per-watch event
filtering is not implemented. Listings only contain names the host directory
actually has: missing bind mountpoints are not synthesized.

Content reads from FDs (read/readv/pread/preadv/preadv2, the source of
sendfile/splice/tee/copy_file_range, fgetxattr/flistxattr, empty-path
readlinkat and every file mmap including MAP_PRIVATE) follow the FD's mount
origin. Pipes, socketpairs, sockets, accepted sockets, eventfd, timerfd,
signalfd, epoll, inotify and memfd created inside the guest carry a local
stream grant that is kept across dup/fork, cleared on exec and never
serialized. Unknown FDs (inherited, imported or restored after exec) are denied
by default. `--allow-stream-input` admits them only when fstat reports a pipe
or socket, or a character device that answers TCGETS; invalid FDs still return
EBADF first. Combine it with `--revalidate-file-fds` for file redirections that
cross exec. name_to_handle_at is not bridged and returns ENOSYS in this mode.

Exec chains read the target's PT_INTERP in the payload and resolve it with guest
symlink semantics and the read policy; the child loader loads exactly that host
path (`--exec-interp`) and refuses a dynamic target without one. A hidden or
ancestor-only interpreter refuses the exec. Merged-usr `/lib` is a symlink in
the root, so profiles must expose the interpreter's guest path explicitly.

Known gaps: the launcher's initial target still maps PT_INTERP lexically;
ancestor stat reports host metadata; UNIX socket paths, xattrat
entries and path races are not covered. `test/fs_policy/reads.py` covers the
probe matrix plus protected Alpine/Ubuntu shells (read-only system tree, pipes,
command substitution, redirection, filtered `ls /`).
