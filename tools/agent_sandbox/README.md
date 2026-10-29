# Agent filesystem profiles (planning prototype)

The primary product direction is an agent filesystem sandbox using existing
system/brew tools. A separate Linux rootfs is a secondary mode. This repository
contains the ELF execution backend and vendored PRoot path semantics together;
bubblewrap is not a build or runtime dependency.

`plan.py` currently validates and prints a filesystem plan only. It does not
launch an agent, create directories, or enforce access. The output explicitly
marks enforcement as `not-connected`; do not pass the plan to the legacy bind
CLI expecting readonly or default-deny isolation.

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

Next implementation steps:

1. Carry validated policy in loader/payload configuration and across exec;
   reject policy configurations that exceed backend limits.
2. Connect default-deny visibility and readonly checks to canonical path
   resolution, including both operands of rename/link and metadata mutation.
3. Track descriptor provenance and permissions, including inherited FDs,
   dup/close, writable mmap and descriptor-based mutations. Filter directory
   listings and handle traversal of ancestors needed to reach exposed paths.
4. Create private state and clean environment for launch; validate actual brew
   programs and their dynamic loaders in the system sandbox.
5. Close known interception bypasses before claiming hostile-agent isolation.

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
