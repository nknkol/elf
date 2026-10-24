# SVC interception probe (HarmonyOS AArch64)

Tested on 2026-10-24 in the existing HarmonyOS sandbox. Only creates/reads
`host.txt` and `mapped.txt` in this directory. No host sandbox escape is tested.

From the repository root:

```sh
python3 opt/elf/test/svc_probe/build.py
python3 opt/elf/test/svc_probe/run.py
```

Tool: `opt/elf/src/elfloader`. Full logs: `build.log`, `native-*.log`,
`loader-*.log`, and `results.json` in this directory.

The test binds the guest path `host.txt` to the backing file `mapped.txt`,
using `--mode compat -v mapped.txt:host.txt`. The normal call must therefore
read `GUEST_MAPPED`, whereas bypassing the bind reads `HOST_ORIGINAL`.
Both files remain accessible under the outer sandbox's permissions.

| Mode | Operation | Native | Through loader |
| --- | --- | --- | --- |
| b | Existing text SVC / openat | HOST_ORIGINAL | GUEST_MAPPED |
| r | Anonymous RW, emit SVC, mprotect RX | HOST_ORIGINAL | GUEST_MAPPED |
| a | Anonymous RWX, emit SVC after mmap | openat returns -2 | openat returns -2 |
| x | Anonymous RW, mprotect RWX, then emit SVC | openat returns -2 | openat returns -2 |
| p | Call payload raw_syscall directly | No hook stub; skipped | HOST_ORIGINAL |

## Interpretation

- Runtime RW->RX scanning works: the SVC word becomes a branch and the read
  honors the bind. The anonymous-memory coverage claim is confirmed here.
- The two RWX cases did NOT demonstrate successful file access bypass.
  Mapping and execution returned, but openat returned ENOENT even natively.
  The cause of this platform behavior has not been established by this test.
- Mode p is a white-box test: build-time `llvm-nm` supplies the relative
  offset of raw_syscall from payload entry. At runtime the demo decodes the
  branch installed at its own SVC, reads payload entry from the stub's data,
  and calls raw_syscall. It does not read /proc/maps, modify hooks/config,
  or ask the loader to omit scanning. ASLR addresses are resolved at runtime.
  This demonstrates a bypass of this build's bind rewriting, not a generic
  black-box exploit or a bypass of HarmonyOS permissions.

## Build adaptations

Production source/Hook logic is unchanged. Clang emits memcpy/memset calls
in this freestanding build. `runtime.c` supplies minimal implementations to
both loader and payload. Before this adaptation, the loader failed to link;
with only the loader adapted, runtime RW->RX hooking crashed on payload's
unresolved memcpy PLT entry. `first-results.json` preserves that initial run.

The build embeds `/bin/sh` in place of the missing external dash artifact;
the shell/init path is not exercised by this demo. The demo is a static,
libc-free executable, and uses the local compiler's automatic signing.

Scope: single-threaded bind test; no rootfs-wide, concurrent, exec-chain,
network, or exhaustive security validation. Fixes may legitimately change
these expected results; inspect logs rather than preserving bypass behavior.
