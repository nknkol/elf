# Native syscall survey and dispatcher verification

Run from the ELF repository root on the target AArch64 host:

```sh
python3 tools/syscalls/scan.py --output /tmp/native-syscalls.json
python3 test/syscalls/check_dispatch.py
python3 vendor/proot/svc/build_elf.py
python3 test/syscalls/check_runtime.py
```

The scanner obtains syscall numbers from the active clang `<asm/unistd.h>`.
It invokes each explicit recipe through Python ctypes in a separate process,
with a three-second timeout, core dumps disabled and disposable file fixtures.
It never blindly invokes all numbers. Returned errors, signal deaths, timeouts,
probe errors and names absent from headers are distinct report states.

`test/syscalls/native-harmonyos.json` records this host's native scan:
296 syscall names found in headers; 90 executed recipes, plus one alias absent
from headers. 32 returned success, 52 returned errno, and six terminated with
SIGSYS: rseq, clone3, openat2, open_by_handle_at, io_uring_enter and
io_uring_register. Invalid-FD/invalid-argument results establish only that those
specific arguments returned without a fatal signal. Header presence does not
establish kernel support, and this report does not characterize every syscall
or every possible argument. In particular io_uring_setup returned an error for
the tested invalid input; this does not establish that usable rings can be
created. No mount, namespace, reboot, ptrace or arbitrary process-control probe
is performed. The local porting cheatsheet describes sandbox restrictions but
is not a syscall allowlist; measured results remain parameter-specific.

The payload uses an explicit `slow_syscalls.inc` inventory for filesystem,
FD, mapping, namespace and compatibility calls. Other ordinary and unknown
numbers remain fast. clone and rt_sigreturn bypass in the generated stub before
changing SP; exit/exit_group stay outside the reentry guard. The earlier
all-number-dispatch experiment was replaced after reviewing thread/stack
constraints. There is no actual guest clone preflight in the C dispatcher.

SYS_* constants alias target __NR_* definitions, correcting rt_sigaction to
134. The four newly observed fatal interfaces return ENOSYS on HarmonyOS;
rseq/clone3 already did so. This is conservative platform compatibility, not
runtime policy discovery or openat2/io_uring emulation.

The assembly regression checks every selected number with a sentinel dispatcher
and also verifies fast calls. Native/loader tests cover real signal return and
clone with a new child stack. The complete history, limits and regression
requirements are in [engine lessons](../../docs/SYSCALL_ENGINE_LESSONS.md).
