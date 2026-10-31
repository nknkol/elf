# Native vs loader micro benchmarks

`make bench` (or `python3 test/bench/bench.py --runs N` after both builds)
runs `test/bench/bench.c`, a static raw-syscall program, natively and under
four loader configurations, and prints median nanoseconds per operation.
It is not part of `make check`: absolute numbers depend on the device, its
storage backing and load. Compare ratios on the same device and build.

| Configuration | Meaning |
| --- | --- |
| native | the program without the loader |
| default | `elfloader`: PRoot path translation, no FD metadata |
| experiment | FD experiment without policy options |
| mutation | `--guard-file-mutations dw` |
| guarded | `--guard-file-access dw` (reads, visibility and mutations) |

Cases: `getpid` (fast path through the SVC stub), `fstat` (lightweight FD
slow path), `stat` and `open_close` (full guest path resolution of
`/work/bench/file`), 4 KiB `pread`/`pwrite` (FD checks then native IO),
`readdir_64` (open + getdents64 of 64 entries + close) and an anonymous
64 KiB `mmap`/`munmap` pair.

## HarmonyOS, 2026-10-30

HongMeng Kernel 1.13.0 AArch64, project tree on `/storage/Users`, median of
five runs, ns/op. Native `stat` costs about 10 us here because every host
lookup walks a long path on the shared storage backing.

| case | native | default | experiment | mutation | guarded | default/x | guarded/x |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| getpid | 224 | 308 | 365 | 353 | 352 | 1.4 | 1.6 |
| fstat | 849 | 1148 | 1578 | 1601 | 1668 | 1.4 | 2.0 |
| stat | 10422 | 32119 | 32592 | 32558 | 32906 | 3.1 | 3.2 |
| open_close | 17356 | 42366 | 43354 | 43362 | 43612 | 2.4 | 2.5 |
| pread_4k | 802 | 1270 | 1477 | 1471 | 1480 | 1.6 | 1.8 |
| pwrite_4k | 1560 | 2009 | 2220 | 2234 | 2225 | 1.3 | 1.4 |
| readdir_64 | 76679 | 103403 | 104894 | 105573 | 115982 | 1.3 | 1.5 |
| mmap_64k | 1531 | 2519 | 2880 | 3133 | 3075 | 1.6 | 2.0 |

Before this round the same device measured `stat` 6.2x/6.7x,
`open_close` 4.4x/4.9x, guarded `readdir_64` 3.1x and guarded `mmap_64k`
27.9x (default/guarded). The changes:

- The payload was compiled with `-O0`, so every intercepted call ran
  unoptimized code and byte-wise struct copies (the mapping admission table
  zeroed and copied 2 KiB per mmap/munmap). It is now built with `-O2`.
  That required the loader to apply the payload's `R_AARCH64_RELATIVE`
  relocations, which it never did; even the `-O0` payload carried two
  unrelocated GOT entries. Other dynamic relocation types are refused.
- Path calls took a fresh scratch mapping (mmap, page faults, munmap) each
  time. A small per-process pool of scratch bridges is reused; a vfork
  child keeps its reserved scratch.
- PRoot resolution lstats every component, and each host lstat walks the
  full host path. Lookups whose answer cannot change resolution are
  skipped: the root and bind mount points (configured host paths, followed
  by the kernel) and a final name that the call does not follow.

The remaining path overhead is roughly two host lstats per call (the
intermediate directory and the followed final name), the work PRoot's
symlink-preserving canonicalization requires. FD IO adds a metadata lookup
and stays within about 0.5-0.7 us of native.

## HarmonyOS, 2026-10-30 (second round)

Same device and method, after PRoot-parity work (glue, fake ids, exec
changes) and two lookup savings:

| case | native | default | experiment | mutation | guarded | default/x | guarded/x |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| getpid | 231 | 358 | 335 | 345 | 330 | 1.5 | 1.4 |
| fstat | 912 | 1368 | 1547 | 1619 | 1624 | 1.5 | 1.8 |
| stat | 10600 | 24991 | 25142 | 25177 | 25585 | 2.4 | 2.4 |
| open_close | 17504 | 31200 | 32503 | 32448 | 33046 | 1.8 | 1.9 |
| pread_4k | 804 | 1281 | 1490 | 1491 | 1491 | 1.6 | 1.9 |
| pwrite_4k | 1492 | 1982 | 2190 | 2198 | 2197 | 1.3 | 1.5 |
| readdir_64 | 72912 | 75955 | 77435 | 77251 | 104218 | 1.0 | 1.4 |
| mmap_64k | 1533 | 2422 | 2800 | 3131 | 3195 | 1.6 | 2.1 |

(getpid varies by about 100 ns between runs; it is the unchanged fast path.)

- A followed stat used three host walks: the parent, an lstat of the final
  name, then the stat itself. When the final lstat finds no symlink its
  result is the answer; the kernel still copies it (process_vm_writev to
  ourselves), so an unwritable buffer stays EFAULT.
- A followed open (not O_PATH, no trailing slash) skips the final lstat and
  opens with O_NOFOLLOW. ELOOP means the final name is a symlink and the
  path is resolved again in guest terms. Any failure of the shortened
  resolution, policy refusals included, is also resolved again with the full
  lookup, so decisions never depend on an unfollowed final symlink.

## HarmonyOS, 2026-10-31: isolation mode (`--isolate`)

Two more configurations: `isolate` (default build) and `isolate-g`
(guarded build, `--guard-file-access dw`), both with the broker and the
guest filter. Same device and method; the device was slower and noisier
this day (native `stat` 9.8-12 us, single runs vary by up to 50%).

Before this round, isolation cost `stat` 105 us, `open_close` 85 us and
guarded `readdir_64` 243-367 us. After:

| case | native | default | guarded | isolate | isolate-g |
| --- | ---: | ---: | ---: | ---: | ---: |
| getpid | 209 | 296 | 281 | 268 | 327 |
| fstat | 784 | 1311 | 1578 | 1380 | 1599 |
| stat | 9809 | 24672 | 35900 | 66564 | 61421 |
| open_close | 17250 | 31793 | 40489 | 91886 | 92510 |
| pread_4k | 923 | 1477 | 1769 | 1897 | 2000 |
| pwrite_4k | 1775 | 2312 | 2605 | 2337 | 2584 |
| readdir_64 | 80982 | 85430 | 122634 | 163080 | 176979 |
| mmap_64k | 1760 | 2697 | 3618 | 2820 | 3775 |

(An earlier run the same day measured `stat` at 45 us for both isolated
configurations.) Calls that name no path (fstat, IO, mmap) cost the same as
without the broker.

Where the time goes (`test/isolation/probe.c` mode `rtt`, ns per op):
a SEQPACKET ping-pong between two processes without the broker costs
15-26 us on HongMeng, 35 us when an FD comes back (SCM_RIGHTS); an empty
broker request 22-37 us, a broker lstat 34-44 us, a broker open 43 us. The
broker's own path walk is a few microseconds: a path call costs about one
process round trip, so the work was to need fewer of them.

- Optimistic resolution: the payload maps a guest path lexically, without
  asking the broker about each component, and sends the final call with
  BROKER_STRICT; the broker refuses with ELOOP if any symlink is on the
  way (a final one too when the call follows it) and reports which one
  and its target. The call then runs again with that symlink known, still
  optimistically, so each symlink costs one more round trip instead of a
  full lookup per component. Paths with "..", /proc, ancestors of nested
  bind mount points and link targets with a ".." after a name are resolved
  fully. A guest `stat` went from three requests to one.
- The copy of a reused stat result used process_vm_writev on ourselves,
  which the guest filter refuses; that cost a second stat through the
  broker. Optimistic resolution no longer needs the reuse.
- Exec opens the program, script interpreters and PT_INTERP with the same
  optimistic resolve-and-open (one request each); the execute permission
  is checked from fstat instead of access(X_OK). A busybox applet exec
  went from 12 requests to 3.
- The owners fake_id0 reports as root are looked up once by the initial
  loader and passed to every child (two lookups per process before).
- Guarded listings keep the guest name of an open directory per FD while
  its dev/ino is unchanged (every getdents call named it again).

## HarmonyOS, 2026-10-31: isolation round two (shared channel area)

A broker request cost about one process round trip, and a round trip was
almost all scheduler latency: putting a process to sleep and waking it.
Measured between two guest processes (load average about 17, 20 CPUs):
SEQPACKET 18-19 us, pipe 15 us, futex 10-16 us, futex with both sides
spinning first 1.5-2 us. Each channel now has a shared area (a sealed
memfd made by the broker, docs/ISOLATION.md); both sides spin on it before
sleeping on the channel socket, which still carries FDs, wakeups and end
of file.

`test/isolation/probe.c` mode `rtt`, old (be4c2f1) and new loader run at
the same time, two rounds, ns per op:

| | old | new |
| --- | ---: | ---: |
| empty request | 29221 / 39777 | 1825 / 1213 |
| broker lstat | 36301 / 61955 | 7270 / 6290 |
| broker open (FD back) | 57428 / 76331 | 24862 / 21435 |
| guest stat | 45957 / 72723 | 8795 / 11312 |

`make bench` afterwards (load average 22):

| case | native | default | guarded | isolate | isolate-g |
| --- | ---: | ---: | ---: | ---: | ---: |
| getpid | 269 | 274 | 375 | 289 | 299 |
| fstat | 758 | 1332 | 1514 | 1169 | 1467 |
| stat | 8583 | 21260 | 30261 | 16869 | 18330 |
| open_close | 14364 | 27237 | 33816 | 37562 | 38973 |
| pread_4k | 801 | 1286 | 1505 | 1281 | 1493 |
| pwrite_4k | 1493 | 1983 | 2219 | 2080 | 2198 |
| readdir_64 | 71629 | 73832 | 105922 | 91491 | 105384 |
| mmap_64k | 1531 | 2336 | 3060 | 2532 | 3192 |

An isolated `stat` is now cheaper than the in-process default: one lexical
mapping and one request, where the default walks the path itself. Calls
that bring an FD back (open) still pay for SCM_RIGHTS on the socket.
