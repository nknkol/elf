#!/usr/bin/env python3
"""Real file mapping guards and kernel-backed private/shared memory behavior."""
import os
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
with tempfile.TemporaryDirectory(prefix='mapping-guard-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw'):
        (root / name).mkdir()
        (root / name / 'file').write_bytes(b'seed' + bytes(os.sysconf('SC_PAGE_SIZE')-4))
    (root / 'root-file').write_bytes(b'denied')
    before = (root / 'ro/file').stat()
    subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', '-DPAGE_SIZE='+str(os.sysconf('SC_PAGE_SIZE')), str(repo / 'test/fs_policy/mappings.c'),
                    '-o', str(root / 'probe')], check=True)
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                        '-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw',
                        '--guard-file-mutations', 'drw', '--', './probe'],
                       cwd=root, capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    assert p.stdout == '', p.stdout
    assert (root / 'rw/file').read_bytes() == b'Meed' + bytes(os.sysconf('SC_PAGE_SIZE')-4)
    assert (root / 'ro/file').read_bytes() == b'seed' + bytes(os.sysconf('SC_PAGE_SIZE')-4)
    assert (root / 'root-file').read_bytes() == b'denied'
    after = (root / 'ro/file').stat()
    assert (before.st_mode, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_mode, after.st_mtime_ns, after.st_ctime_ns)
    print('PASS: shared/COW mappings, upgrades, unmap/fixed holes, fork/remap/exec and host state')
