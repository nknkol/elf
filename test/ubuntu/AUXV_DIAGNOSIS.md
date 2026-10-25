# Ubuntu Rust coreutils auxv failure diagnosis

Observed on 2026-10-25 in the `com.huawei.hmos.hishell` terminal sandbox.
The original diagnosis is retained below. The implemented fix is described at
the end; guest PR_GET_AUXV now works.

## Faultlogger correlation

`/proc/self/cgroup` identifies the terminal package as
`com.huawei.hmos.hishell`. Only that package's records were inspected under
`/data/log/faultlog/faultlogger/`.

The latest matching records available during the investigation were dated
2026-10-24 20:37:16–23 (timestamps as written by faultlogger). All six identify
Python as the process and `SIGSYS(SYS_SECCOMP)` as the reason, for syscall
numbers 426, 427, 265, 293, 435 and 437. They corroborate the earlier isolated
native syscall survey, not the Ubuntu Rust failure. No matching new Rust
coreutils crash record appeared after reproducing the failure. The reason
for that lack of a system crash record is not established.

The reproduced guest stderr prints a Rust panic followed by `Aborted (core
dumped)`, with shell status 134, at rustix
`backend/linux_raw/param/auxv.rs:269:22`. This is an abort after failed auxv
initialization, not evidence of a SIGSEGV or another sandbox SIGSYS.

## Targeted probes and control

Inside the same Ubuntu guest, Perl was used to issue
`prctl(0x41555856 /* PR_GET_AUXV */, buffer, 1024, 0, 0)` and open
`/proc/self/auxv`. Results:

- PR_GET_AUXV: -1, errno EINVAL.
- /proc/self/auxv: ENOENT.
- Unmodified `ls --version`: status 134, auxv initialization panic.

For a diagnostic control only, an empty `/proc/self` directory was created in
the disposable root and host `/proc/self/auxv` was bound to that guest path.
The auxv panic disappeared, but the command exited 1 with:

```
coreutils: unknown program 'elfloader-proot'
```

This isolates the missing auxv retrieval path as the immediate panic trigger.
It also demonstrates that exposing the host auxv is not a valid fix: that data
identifies the executable loaded by the kernel, namely the loader. The exact
coreutils code path selecting that name was not independently symbolized.
The diagnostic binding is not part of the acceptance harness or default config.

As a supporting source, rustix v1.1.3's
[auxv implementation](https://github.com/bytecodealliance/rustix/blob/v1.1.3/src/backend/linux_raw/param/auxv.rs)
tries PR_GET_AUXV and falls back to /proc/self/auxv, returning Err(()) if both
fail. This source illustrates the failure mechanism; it is not a claim that
the distro binary uses exactly that upstream version or identical line numbers.

## Required fix

Expose the guest auxiliary vector produced by the loader, consistent with the
vector placed on its startup stack. Include guest executable identity and
program/interpreter addresses, not the kernel's loader identity. Its pointer
values must remain valid in that guest process and be rebuilt across exec.
Both PR_GET_AUXV and /proc/self/auxv need deliberate support or explicitly
compatible fallback semantics. Do not broadly bind host /proc to hide this
missing interface. Add Rust ls/cat and guest-vs-host identity checks when the
implementation is ready.

No system crash logs, hardware fingerprints or full memory maps are committed.


## Implemented fix and validation

The loader snapshots its rewritten auxv, including AT_NULL, before compacting
argv/env on the guest stack. The PROOT_PATH payload configuration carries up to
64 pairs; larger vectors stop loader startup explicitly. Every exec reconstructs
this snapshot. Static executables now receive AT_BASE=0 instead of retaining
the loader's interpreter base. These changes require a matching rebuilt loader
and payload; the experimental config extension is compiled only with PROOT_PATH.

PR_GET_AUXV returns this guest snapshot, including guest AT_EXECFN and guest
program/interpreter pointers. Zero-length queries return the snapshot length;
short buffers receive only their requested prefix while the result reports the
full length. Nonzero reserved arguments return EINVAL. An ephemeral CLOEXEC
memfd plus kernel pread copies to the caller, so invalid buffers return EFAULT
rather than faulting in payload memcpy. The FD is closed before returning.
This uncommon initialization interface has extra syscalls and can fail with
resource errors such as EMFILE; it is not the final performance design.

The return-length/truncation/error convention follows Linux's
[prctl_get_auxv implementation](https://github.com/torvalds/linux/blob/v6.6/kernel/sys.c).
The emulated saved vector ends at AT_NULL rather than reproducing the kernel's
fixed-sized storage padding. /proc/self/auxv is still not virtualized; the
working route is PR_GET_AUXV, used by this image's rustix implementation.

`vendor/proot/port-tests/test_auxv.py` checks the snapshot word-for-word against
the startup stack, executable identity, static AT_BASE, zero/short buffers,
invalid pointers and reserved flags. Both compat/container and exec chaining
are covered. Ubuntu now passes all 18 cases, including Rust ls/cat; Alpine's
18 cases and the existing filesystem, exec, metadata, guard, dispatch and SVC
regressions also pass. No diagnostic host-auxv bind is used in those tests.
