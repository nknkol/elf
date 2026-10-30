#!/usr/bin/env python3
"""The guest's own fault handling works as it would natively.

A SIGSEGV handler the guest installs is really installed (queried back and
run on a fault); without one the program dies of SIGSEGV itself rather
than exiting with a status. Both builds."""
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: rootfs unavailable:', alpine)
    raise SystemExit(0)
with tempfile.TemporaryDirectory(prefix='segv-', dir=build) as tmp:
    probe = Path(tmp) / 'probe'
    subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-Wl,-e,_start', str(repo / 'test/fs_policy/segv_probe.c'),
                    '-o', str(probe)], check=True)
    for suffix in ('', '-fd-experiment'):
        loader = build / f'elfloader-proot{suffix}'
        def run(mode):
            return subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                                   '-v', f'{tmp}:/work', '--', './bin/busybox', 'sh', '-c',
                                   f'exec /work/probe {mode}'],
                                  cwd=alpine, capture_output=True, text=True, timeout=60)
        p = run('h')
        assert (p.returncode, p.stdout) == (0, 'installed\nhandled\n'), (suffix, p.returncode, p.stdout)
        p = run('d')
        assert p.returncode == -11 and p.stdout == '', (suffix, p.returncode, p.stdout)
        print('PASS: guest SIGSEGV handlers install and run; unhandled faults kill by signal:',
              loader.name)
