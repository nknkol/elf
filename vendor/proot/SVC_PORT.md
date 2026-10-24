# HarmonyOS SVC port

## Decision and deployment constraints

Use upstream C PRoot as the source of filesystem semantics, and the existing
AArch64 ELF engine as the source of loading/instruction-patching mechanisms.
The system sandbox is the deployment boundary. ptrace and an additional
sandbox are not options. This is not a Rust port or an integration into bubblewrap.

## Implemented

- Upstream source imported with revision recorded in UPSTREAM.md.
- FileSystemNameSpace separated from Tracee (layout unchanged).
- Path enums and pure helpers extracted into path_types.h/path_helpers.c.
- The existing canonicalize algorithm moved to canon_core.c. All filesystem
  lookups/readlink/proc/detranslation go through explicit PathOps callbacks.
  The legacy canonicalize entry in canon.c supplies adapters for the original
  Tracee/glue/extensions/proc behavior; both backends share one algorithm.
- resolve_core.c provides absolute/cwd/dirfd entry resolution with explicit
  directory-FD and final host mapping callbacks. It rejects empty pathnames;
  AT_EMPTY_PATH remains the responsibility of syscall/FD dispatch.
- binding_core.c now shares component-prefix matching and checked prefix
  substitution with the legacy binding.c. Replacement overflow is propagated
  as -ENAMETOOLONG instead of silently ignoring substitute_path_prefix's error.
- A caller-owned immutable BindingTable supports longest-prefix nested binds,
  last-entry-wins duplicate guest destinations, symmetric binds, root fallback
  and rootfs precedence during reverse lookup. Spelling is validated before
  publication; no talloc or global mutable state is used.
- The filesystem harness now calls BindingTable for both forward mapping and
  directory-FD reverse mapping instead of hard-coded /mnt prefix replacement.
- Readlink failures in the legacy adapter now return negative errno instead
  of the previous raw -1. This is an intentional error-reporting correction.

Run `sh vendor/proot/port-tests/check.sh` from the ELF repository root. It compiles
without ptrace/talloc and runs 29 binding checks plus 28 real-filesystem checks, including link/..,
absolute symlinks inside binds, final nofollow, missing components, trailing
slash, loops, bound directory FDs, and a directory FD surviving rename.
The harness uses a one-bind configuration of the shared binding core; its
stat/readlink callbacks still use host libc. Tests
run inside a temporary directory and remove their artifacts automatically.

An experimental ELF path bridge is now runnable (see below); this is not
full SVC-backed PRoot. Host-backed bind initialization/glue, FD lifecycle,
extensions and /proc adaptation are outstanding. /proc links are explicitly
unsupported in the new bridge. The full legacy build is
not validated: local pkg-config cannot locate talloc development files.

## Dependency map and next migration steps

1. src/path/path.c: translate_path uses Tracee, cwd, directory FD resolution,
   logging and extension events. The independent resolve_core now supplies the base-path entry, but production
   mapping and extension adapters still need implementation.
2. src/path/canon.c and binding.c now use shared core operations. The new
   immutable table uses caller-owned initialized prefixes. Next adapt
   initialization/glue and filesystem existence checks to host callbacks.
   Preserve ownership rules when configurations are published to threads.
3. src/path/proc.c: virtual /proc interpretation must distinguish guest-visible
   paths from runtime metadata. Validate actual host access, not assumptions.
4. src/syscall/enter.c and exit.c: inventory entry/exit transformations before
   adapting them to an in-process syscall request/result interface. Do not
   import register-peeking or ptrace memory operations into the new core.
5. Adapt ELF's syscall dispatcher to the resulting API. Define ownership,
   reentry, per-thread vs shared FS state, fork/clone/exec inheritance first.

## Next functional acceptance target

The libc-hosted semantic harness now resolves a root and bind correctly for:
absolute paths, cwd-relative paths, directory-FD-relative paths, symlinks
(including link/..), missing final components and no-follow final components.
Directory-rename/FD and expected-errno checks also pass. ELF now supplies a freestanding string runtime and raw-syscall
stat/readlink/FD callbacks. Its adapter consumes the existing root/bind configuration and passes 81 filesystem and 15 exec
end-to-end checks. Mutation and exec milestones are detailed below. Next:
agent policy configuration, default-deny visibility and read-only enforcement.

## Existing ELF evidence

See ../../test/svc_probe/README.md. Initial and anonymous RW->RX interception
worked locally. Direct payload raw_syscall invocation bypassed a bind in a
white-box test. RWX post-scan writes succeeded but file access returned ENOENT;
the cause is not established. The new port does not claim these are resolved.

All integration sources and this vendored PRoot tree are tracked together
on the ELF branch feat/proot-svc-bridge. No bubblewrap checkout is required.

## Scope deferred

Strong isolation from hostile in-process code, full /proc virtualization,
read-only mount equivalence, merged directory overlays and network/PID
virtualization are not delivered by this initial extraction.

## Standalone path library

`make -C vendor/proot/svc` builds `svc/build/libproot_path.a` with freestanding,
PIC, no-stack-protector compilation. No ptrace, talloc, or libc is linked.
`svc/build/undefined-symbols.txt` inventories the remaining runtime imports:
assert handling, memory/string functions, and sscanf (the inherited proc-FD
assertion). The standalone archive remains a debug build. The experimental ELF build
compiles those same sources as separate NDEBUG objects (avoiding the inherited
assert/sscanf dependency), and links svc/runtime.c without host libc.

Reverse mapping is a pathname policy, not an FD identity model. Multiple guest
aliases for the same host directory select a deterministic representative;
retaining the original guest mount identity, overwritten binds, unlinked
open directories, and concurrent rename races require future FD tracking.
Initialization currently rejects noncanonical bind spelling and root entries
in the bind array; root has a separate field. It does not auto-resolve host
symlinks or create missing guest mountpoints. These limitations are explicit.

## Experimental ELF path integration

Build and test from the ELF repository root:

```sh
python3 vendor/proot/svc/build_elf.py
python3 vendor/proot/port-tests/test_svc.py
python3 vendor/proot/port-tests/test_exec.py
make -C vendor/proot/svc check
```

The build opts in with PROOT_PATH=1 and forces all objects to rebuild. Its
signed tool snapshot is svc/build/elfloader-proot; the payload links with
--no-undefined. The success manifest is invalidated before rebuilding and
records the snapshot SHA-256; tests check it before running. Snapshot updates
use rename because this host forbids overwriting an already signed binary.
The default ELF backend remains available via its original build script.
Switching backends requires a full rebuild; incremental mode switching is
not supported yet.

openat, newfstatat, statx, readlinkat, chdir, fchdir, getcwd, faccessat and
faccessat2 are routed to logic/proot_bridge.c. They use the shared PRoot core,
raw newfstatat/readlinkat/fstat/getcwd, and per-call mmap scratch. Root and up
to eight binds come from existing ELF config (still 256-byte config fields).
mkdirat, unlinkat, symlinkat, linkat, renameat and renameat2 also use this
bridge. execve/execveat use proot_exec.c and the same resolver. Remaining
pathname syscalls still use legacy behavior.
The assembly dispatch filter now admits fchdir when PROOT_PATH is enabled.
Overlay configurations and virtual proc symlinks return EOPNOTSUPP on this
path. This mixed backend is for controlled tests, not general rootfs use.

The callback table is assigned field-by-field at runtime because the current
loader does not relocate static payload function-pointer tables. PRoot's
join_paths is renamed to proot_join_paths at compile time to avoid collision
with the legacy ELF helper of a different signature. Kernel struct stat size
and mode offset are asserted for AArch64, and flags come from target Linux
headers (not generic hard-coded O_NOFOLLOW values).

81 filesystem end-to-end tests pass: root-relative/absolute access, bind, symlink order,
absolute and relative symlinks inside binds, directory FDs, final nofollow,
exclusive creation, missing-file creation, errno cases, loops, metadata,
readlink truncation/byte preservation, cwd changes, access checks, and proc
rejection. getcwd returns the raw syscall byte count including its NUL and
reports ERANGE without copying when the guest buffer is too small. readlink
preserves ordinary target bytes and relies on the kernel for no-NUL output
and truncation. fchdir verifies directory type and visibility before changing
host cwd. Multiple aliases still lack original guest mount identity. FD-after-rename uses a host-assisted rename handshake; it
does not claim the legacy guest renameat path works. Logs are in
svc/build/svc-results.json. The 29 binding + 28 hosted path tests also pass.
The original SVC probe passes its expectations, including reproducing the
known raw_syscall-entry bind bypass; that security boundary is unchanged.

Unresolved: safe copying from arbitrary guest pointers, atomic config/FD
lifecycle, unlinked directory identity, pathname races and recursive-walk
stack cost. No performance or multithreaded correctness claim is made.

## Metadata host compatibility

The native controls in svc/build/native-metadata-controls.json reproduce a
host difference: fstatat/statx with AT_EMPTY_PATH on an O_PATH|O_NOFOLLOW
symlink FD reported the parent directory; fstat on that FD reported the
symlink itself. The bridge uses fstat for newfstatat empty-path FD requests,
validates accepted flags, and uses a dot lookup for AT_FDCWD. Empty-path statx
adds AT_SYMLINK_NOFOLLOW to retain FD identity. These paths are covered by
end-to-end symlink-type checks. This is a targeted compatibility adjustment,
not wholesale stat emulation.

AT_EMPTY_PATH metadata and empty-path readlink intentionally operate on the
existing FD without translating a pathname. Inherited FD policy and guest
pointer fault containment are not implemented. For virtual /proc symlinks,
pathname readlink returns EOPNOTSUPP rather than leaking a translated target.

## Mutation and execution milestone

Mutation tests additionally cover two directory FDs, symlink replacement,
renameat2 NOREPLACE/EXCHANGE and host postconditions. Distinct configured
mounts return EXDEV for rename/link, even when backed by the same host
filesystem. Removing or renaming mountpoints or their ancestors returns
EBUSY conservatively; this is not complete Linux mount-rename emulation.
Native hardlinks return EPERM in this sandbox: those checks validate error
propagation against native controls, not successful hardlink creation.
Empty-path hardlinks remain unsupported without FD mount identity tracking.

15 exec checks pass using static AArch64 guests. The signed loader is
re-executed with root/binds and caller argv/env preserved, including an empty
environment and explicit environment in container mode. Child cwd survives.
Path-based execveat resolves directory FDs and honors final nofollow. A
single shebang interpreter is resolved through the same guest filesystem;
its optional argument remains a single string. Missing, nonexecutable,
invalid-format and truncated-header files return errors to the caller.

Limits: FD exec (AT_EMPTY_PATH), nested script interpreters, custom hook
ranges and colon-bearing bind serialization explicitly return EOPNOTSUPP.
Exec paths remain bounded by 256-byte config fields, with fewer than 128
caller arguments. Script argv uses the canonical guest script pathname.
ELF preflight checks the ELF64 AArch64 header, not every segment or program
header; later loader failures are not guaranteed to return exec errno.
Dynamic ELF, multithreaded exec, signal/FD lifecycle and complete auxv
compatibility are not validated by these static tests. No raw target exec
fallback is used. Logs: svc/build/exec-results.json.

## All-number dispatch and native environment survey

The assembly selector has been replaced with all-number slow dispatch; new and
unknown calls no longer silently miss C dispatch. rt_sigreturn retains its
required original-stack path; clone has a preflight stage followed by an
original-stack syscall. ABI constants now come from target headers, correcting
rt_sigaction to 134. Ordinary passthrough calls avoid pathname scratch mmap.
See ../../tools/syscalls/README.md for native probing limits, six measured
SIGSYS cases, compatibility handling and assembly/runtime regression coverage.
This expands dispatch coverage, not the set of completed VFS operations.
