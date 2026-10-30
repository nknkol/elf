#!/usr/bin/env python3
"""Actual path-mutation guards plus host-side no-side-effect checks."""
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
with tempfile.TemporaryDirectory(prefix='path-guard-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw', 'nested'):
        (root / name).mkdir()
        (root / name / 'file').write_bytes(b'unchanged\n')
    (root / 'ro/nested').mkdir()
    (root / 'ro/to_rw').symlink_to('/rw/file')
    (root / 'rw/to_ro').symlink_to('/ro/file')
    before = (root / 'ro/file').stat()
    for option in ('--guard-path-mutations', '--observe-mount-access', None):
        subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector',
                        *([] if option == '--guard-path-mutations' else ['-DOBSERVE_ONLY']),
                        '-I' + str(repo / 'src/payload/include'),
                        str(repo / 'test/fs_policy/path_mutations.c'), '-o', str(root / 'probe.next')], check=True)
        (root / 'probe.next').replace(root / 'probe')
        command = [str(loader), '--mode', 'container', '--root', str(root),
                   '-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw',
                   '-v', f'{root}/nested:/ro/nested',
                   *([option, 'drww'] if option else []), '--', './probe']
        p = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=20)
        assert p.returncode == 0 and 'PASS: path mutation mode' in p.stdout, (option, p.returncode, p.stdout, p.stderr)
        for name in ('ro', 'rw', 'nested'):
            assert (root / name / 'file').read_bytes() == b'unchanged\n'
        assert {p.name for p in (root / 'ro').iterdir()} == {'file', 'nested', 'to_rw'}
        assert {p.name for p in (root / 'rw').iterdir()} == {'file', 'to_ro'}
        assert not (root / 'denied').exists() and not (root / 'unknown').exists()
        after = (root / 'ro/file').stat()
        assert (before.st_mode, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_mode, after.st_mtime_ns, after.st_ctime_ns)
        print('PASS: real path operations, exec and host state:', option or 'legacy')
