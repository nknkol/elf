#!/usr/bin/env python3
"""Many threads at once inside calls the payload handles (many_blocked_probe.c):
each of N threads blocks in openat of its own FIFO, then the main thread
opens the writers. A Go program does this with one thread per blocked
goroutine.

The payload holds per thread in a call a reentry slot, a payload stack and,
with --isolate, a broker channel (until the thread exits). These were 32
(64 guarded), 64 and 64: the next call failed with EAGAIN or EPERM, and the
main thread's own open failed too, so the probe hung; a thread without a
payload stack ran the dispatcher on its own (goroutine-sized) stack.

Expected, both builds, plain and with --isolate: every open succeeds, and
no thread's stack is used deeper than with a single thread (no call fell
back to it). N is 300; the guarded build records at most 128 FDs per
process (FD_POLICY_PLAN.md: ENOSPC beyond), so 100 there."""
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

with tempfile.TemporaryDirectory(prefix='many-blocked-', dir=lib.mode_capable()) as tmp:
    root = Path(tmp)
    subprocess.run(['clang', '-O1', '-static', '-pthread', str(Path(__file__).with_name('many_blocked_probe.c')),
                    '-o', str(root / 'probe')], check=True)
    for suffix, loader in lib.loaders():
        count = 100 if suffix else 300
        for isolate in ([], ['--isolate']):
            what = (loader.name, *isolate)

            def run(n):
                try:
                    p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container',
                                        '--root', str(root), '--', './probe', '/', str(n)], cwd='/',
                                       capture_output=True, text=True, timeout=90)
                except subprocess.TimeoutExpired:
                    raise AssertionError((what, n, 'hung: the writers could not be opened')) from None
                fields = dict(line.split(' ', 1) for line in p.stdout.splitlines() if ' ' in line)
                assert p.returncode == 0 and 'deepest' in fields, (what, n, p.returncode, p.stdout, p.stderr[-800:])
                return fields
            alone = run(1)
            many = run(count)
            assert many['opened'] == f'{count}/{count}' and many['errors'] == '-', (what, many)
            assert int(many['deepest']) <= int(alone['deepest']), (what, alone['deepest'], many['deepest'])
            print(f'PASS: {count} threads blocked in the payload at once, every open done, no thread stack used'
                  f' deeper than one alone ({many["deepest"]} bytes):', *what)
