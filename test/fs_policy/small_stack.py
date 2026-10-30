#!/usr/bin/env python3
"""Intercepted calls fit a vfork child's small spawn stack. Both builds.

The child runs on a 36 KiB stack with a guard page (glibc posix_spawn),
reads /proc/self/fd with getdents64 (CPython) and execs through a chain of
five symlinks (a venv python). Path walking used 8 KiB of stack per link
and the legacy getdents64 reserved 132 KiB, overflowing such stacks."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: rootfs unavailable:', alpine)
    raise SystemExit(0)
with tempfile.TemporaryDirectory(prefix='small-stack-', dir=build) as tmp:
    work = Path(tmp)
    probe = work / 'probe'
    subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-Wl,-e,_start',
                    str(repo / 'test/fs_policy/small_stack_probe.c'), '-o', str(probe)], check=True)
    # Five links, the last named for the busybox applet it runs.
    previous = '/bin/busybox'
    for name in ('c0', 'c1', 'c2', 'c3', 'true'):
        (work / name).symlink_to(previous)
        previous = f'/work/{name}'
    for suffix in ('', '-fd-experiment'):
        loader = build / f'elfloader-proot{suffix}'
        manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
        assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                            '-v', f'{work}:/work', '-v', '/proc:/proc', '--', './bin/busybox', 'sh',
                            '-c', f'exec /work/probe {previous}'], cwd=alpine, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0 and p.stdout.split() == ['child=0'] * 3, (
            suffix, p.returncode, p.stdout, p.stderr[-1500:])
        print('PASS: vfork child on a 36 KiB stack walks 5 symlinks and reads /proc/self/fd:',
              loader.name)
