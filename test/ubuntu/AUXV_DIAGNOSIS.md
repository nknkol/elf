# Ubuntu Rust coreutils auxv failure diagnosis

Observed on 2026-10-25 in the `com.huawei.hmos.hishell` terminal sandbox.
This is diagnosis only; the backend has not yet implemented guest auxv access.

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
