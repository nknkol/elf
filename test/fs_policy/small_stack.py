#!/usr/bin/env python3
"""Intercepted calls fit a vfork child's small spawn stack. Both builds.

The child runs on a 36 KiB stack with a guard page (glibc posix_spawn),
reads /proc/self/fd with getdents64 (CPython) and execs through a chain of
five symlinks (a venv python), or of 15. Path walking used 8 KiB of stack
per link and the legacy getdents64 reserved 132 KiB, overflowing such
stacks. musl's posix_spawn gives its child about 5 KiB (1024 + PATH_MAX,
part of it for musl's own frame); the guarded build's exec once took 10.8
KiB of it and overwrote the parent's frame (make lost its stdout). The
guest stack holds only the stub's frame, the saved general registers and,
in a clone child, the clone path's context; the rest runs on a payload
stack (a Go goroutine has a few hundred bytes below SP at a call, and the
next goroutine's stack after them). The deepest use, the vfork child's
clone return included, must stay within 1280 bytes (1024 measured), with
and without --isolate."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: rootfs unavailable:', alpine)
    raise SystemExit(0)
with tempfile.TemporaryDirectory(prefix='small-stack-', dir=build) as tmp:
    work = Path(tmp)
    probe = work / 'probe'
    subprocess.run([*lib.PROBE, str(repo / 'test/fs_policy/small_stack_probe.c'), '-o', str(probe)], check=True)
    # Five links, the last named for the busybox applet it runs; then a
    # chain of 15: deeper than the frames kept in the bridge, within PRoot's
    # limit of 20 links (MAXSYMLINKS).
    chains = []
    for count in (5, 15):
        previous = '/bin/busybox'
        for k in range(count):
            name = 'true' if k == count - 1 else f'c{count}-{k}'
            (work / f'd{count}').mkdir(exist_ok=True)
            (work / f'd{count}' / name).symlink_to(previous)
            previous = f'/work/d{count}/{name}'
        chains.append(previous)
    BUDGET = 1280
    for suffix in ('', '-guarded'):
        loader = lib.loader(suffix)
        for isolate in ([], ['--isolate']):
            deepest = 0
            for chain in chains:
                p = subprocess.run([str(loader), *isolate, '--mode', 'container', '--root', str(alpine),
                                    '-v', f'{work}:/work', '-v', '/proc:/proc', '--', './bin/busybox', 'sh',
                                    '-c', f'exec /work/probe {chain}'], cwd=alpine, capture_output=True,
                                   text=True, timeout=60)
                lines = p.stdout.split()
                assert p.returncode == 0 and lines[:3] == ['child=0'] * 3, (
                    suffix, isolate, chain, p.returncode, p.stdout, p.stderr[-1500:])
                deepest = max(deepest, int(lines[3].split('=')[1]))
            assert deepest <= BUDGET, (suffix, isolate, f'vfork child used {deepest} bytes of stack')
            print('PASS: vfork child on a 36 KiB stack walks 5 and 15 symlinks and reads /proc/self/fd,'
                  f' {deepest} bytes of stack:', loader.name, *isolate)
