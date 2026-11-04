#!/usr/bin/env python3
"""What Go's runtime counts on from the kernel, at the loader's stubs and
payload (go_abi_probe.c). Go binaries (static, their own raw svc
instructions) crashed on start: the clone child's stack and x28 below.

Expected, both builds, plain and with --isolate:
- clone: data the program put just below the child's new stack (Go: m, g,
  fn and the magic 1234) is still there when the child, after a call of
  its own (gettid), reads it: neither the clone path nor a stub writes
  there (the stubs keep STUB_RED_ZONE bytes below SP);
- x28: a signal arriving while a thread is blocked in a call the payload
  translates (openat of a FIFO) finds the guest's x28 in its handler (Go's
  handler takes its g from x28; the payload never uses the register);
- vfork: a clone with CLONE_VM|CLONE_VFORK and no new stack (Go's os/exec,
  from a goroutine), parent and child on one stack, uses at most 128 bytes
  more of it than an ordinary intercepted call (the clone path's C calls
  run on a payload stack, as every other call's);
- vforks: while one thread's vfork child still holds its parent (sleeping
  a second), another thread's vfork completes at once (the guarded build
  serialized them: a second vfork waited for the first child, or failed)."""
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

with tempfile.TemporaryDirectory(prefix='go-abi-', dir=lib.mode_capable()) as tmp:
    root = Path(tmp)
    probe = root / 'probe'
    subprocess.run(['clang', '-O1', '-static', '-pthread', str(Path(__file__).with_name('go_abi_probe.c')),
                    '-o', str(probe)], check=True)
    for suffix, loader in lib.loaders():
        for isolate in ([], ['--isolate']):
            what = (loader.name, *isolate)

            def run(*argv):
                p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container',
                                    '--root', str(root), '--', './probe', *argv], cwd='/',
                                   capture_output=True, text=True, timeout=60)
                assert p.returncode == 0, (what, argv, p.returncode, p.stdout, p.stderr[-1500:])
                return p.stdout.strip()
            got = run('clone', '-')
            assert got == 'clone 1 below 1234 33 22 11', (what, got)
            got = run('x28', '/fifo')
            assert got == 'x28 kept', (what, got)
            (root / 'fifo').unlink()
            got = run('vfork').split()
            assert got[0] == 'open' and got[2] == 'vfork' and int(got[1]) > 0 and \
                0 < int(got[3]) <= int(got[1]) + 128, (what, got)
            got2 = run('vforks').split()
            assert got2[:2] == ['vforks', 'ok'] and float(got2[2]) < 0.5, (what, got2)
            print('PASS: Go runtime ABI (data below a clone child\'s stack kept across its first call;'
                  ' x28 kept for a signal handler while blocked in the payload; vfork on the caller\'s stack'
                  f' {got[3]} bytes, an openat {got[1]}; a second vfork during one in {got2[2]} s):', *what)
