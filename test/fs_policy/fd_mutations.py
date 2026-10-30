#!/usr/bin/env python3
"""Real FD mutation denial and successful IO, with host-side state verification."""
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
loader = lib.loader('-guarded')
with tempfile.TemporaryDirectory(prefix='fd-guard-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw'):
        (root / name).mkdir()
        (root / name / 'file').write_bytes(b'seed')
    (root / 'root-file').write_bytes(b'denied')
    before = (root / 'ro/file').stat()
    subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', str(repo / 'test/fs_policy/fd_mutations.c'),
                    '-o', str(root / 'probe')], check=True)
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                        '-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw',
                        '--guard-file-mutations', 'drw', '--', './probe'],
                       cwd=root, capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    assert p.stdout == '', p.stdout
    assert (root / 'rw/file').read_bytes() == b'done'
    assert (root / 'ro/file').read_bytes() == b'seed'
    assert (root / 'root-file').read_bytes() == b'denied'
    after = (root / 'ro/file').stat()
    assert (before.st_mode, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_mode, after.st_mtime_ns, after.st_ctime_ns)
    print('PASS: real FD mutation guards, transfer destination, dup/fork/reuse/exec and host state')
