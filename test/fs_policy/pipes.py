#!/usr/bin/env python3
"""Locally created pipe output grants and non-file capability boundaries."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']
with tempfile.TemporaryDirectory(prefix='pipe-guard-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw'):
        (root / name).mkdir()
        (root / name / 'file').write_bytes(b'seed')
    (root / 'root-file').write_bytes(b'denied')
    before = (root / 'ro/file').stat()
    subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', str(repo / 'test/fs_policy/pipes.c'),
                    '-o', str(root / 'probe')], check=True)
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                        '-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw',
                        '--guard-file-mutations', 'drw', '--allow-stdio-output',
                        '--allow-pipe-output', '--', './probe'],
                       cwd=root, capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    assert p.stdout == 'PIPE-OK\n', p.stdout
    assert (root / 'rw/file').read_bytes() == b'seed'
    assert (root / 'ro/file').read_bytes() == b'seed'
    assert (root / 'root-file').read_bytes() == b'denied'
    after = (root / 'ro/file').stat()
    assert (before.st_mode, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_mode, after.st_mtime_ns, after.st_ctime_ns)
    print('PASS: local pipe grants, transfer calls, dup/fork/reuse and exec downgrade')

for directory, shell, prefix, cat, tr in (
        ('alpine-test-root', './bin/busybox', ['sh'], '/bin/busybox cat', '/bin/busybox tr'),
        ('ubuntu-root', './usr/bin/dash', [], '/usr/bin/cat', '/usr/bin/tr')):
    root = build / directory
    if not (root / shell).exists():
        print('SKIP: pipeline rootfs unavailable:', directory)
        continue
    commands = [
        f'printf "pipeline\\n" | {cat} | {tr} a-z A-Z',
        f'value=$(printf "capture\\n" | {cat}); printf "%s\\n" "$value"',
        f'(printf "forked\\n") | {cat}',
    ]
    for command, expected in zip(commands, ('PIPELINE\n', 'capture\n', 'forked\n')):
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                            '--guard-file-mutations', 'r', '--allow-stdio-output',
                            '--allow-pipe-output', '--', shell, *prefix, '-c', command],
                           cwd=root, text=True, capture_output=True, timeout=20)
        assert p.returncode == 0 and p.stdout == expected, (directory, command, p.returncode, p.stdout, p.stderr)
    print('PASS: protected pipeline, command substitution and subshell:', directory)

for args, marker in ((['--allow-pipe-output'], 'pipe output requires file mutation guard'),
                     (['--guard-file-mutations', 'r', '--allow-pipe-output', '--allow-pipe-output'],
                      'duplicate pipe output option')):
    p = subprocess.run([str(loader), *args, '--', '/no-guest-needed'],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode != 0 and marker in p.stdout+p.stderr, (p.stdout, p.stderr)
print('PASS: invalid pipe option combinations rejected')
