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

The payload entry now sends every syscall number, including unknown numbers,
through the slow dispatcher. Important exceptions/details:

- rt_sigreturn executes directly on the original stack, as required by its ABI.
- clone reaches the dispatcher in a preflight-only stage, then releases the
  guard, restores registers/SP, and performs the syscall. Running it from the
  C dispatcher would leave a child with a new stack inside the parent's C
  frames. This stage currently neither modifies nor rejects clone and does
  not implement FD/cwd/thread lifecycle tracking.
- Existing reentry-guard bypass and direct raw_syscall entry remain. All-number
  dispatch is not a claim that hostile guest code cannot bypass interception.
- write no longer bypasses the common dispatcher. Ordinary passthrough calls
  do not allocate the legacy pathname scratch mapping.
- All SYS_* constants in the architecture header now alias target __NR_*
  definitions. This fixes rt_sigaction (134, previously incorrectly 13).
- The four newly observed fatal interfaces return ENOSYS on HarmonyOS;
  rseq/clone3 already returned ENOSYS. Other platforms retain passthrough for
  the four newly gated interfaces. No openat2 or io_uring emulation is claimed.
  The HarmonyOS platform gate is conservative, not runtime policy discovery.

The assembly test uses the real entry.S plus a sentinel dispatcher to verify
1022 numbers (0..1023 excluding rt_sigreturn and clone), without invoking those
kernel interfaces. The runtime test separately executes signal delivery/return
and clone with a new child stack, natively and under the actual loader. It also
checks all six fatal recipes return ENOSYS under the loader. These complement
rather than replace the filesystem, exec and original SVC regression suites.
No multithreaded reentry correctness or performance claim is made.
