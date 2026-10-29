#!/usr/bin/env python3
"""Real pathname xattr mapping, follow semantics and mutation policy."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
normal = '--normal' in sys.argv
suffix = '' if normal else '-fd-experiment'
loader = build / ('elfloader-proot' + suffix)
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / ('elf-build' + suffix + '.json')).read_text())['sha256']
# Probe the actual backing in an isolated child; do not risk SIGSYS in the runner.
with tempfile.TemporaryDirectory(prefix='xattr-', dir=build) as tmp:
    root = Path(tmp)
    capability = root / 'capability'
    capability.touch()
    p = subprocess.run([sys.executable, '-c',
        'import os,sys; p=sys.argv[1]; os.setxattr(p,"user.elf_xattr",b"seed"); '
        'assert os.getxattr(p,"user.elf_xattr")==b"seed"; '
        'assert "user.elf_xattr" in os.listxattr(p); os.removexattr(p,"user.elf_xattr")',
        str(capability)], capture_output=True, text=True, timeout=10)
    assert p.returncode == 0, ('native backing xattr capability required', p.returncode, p.stderr)
    modes = [None] if normal else ['--guard-path-mutations', '--guard-file-mutations',
                                   '--observe-mount-access', None]
    for option in modes:
        for directory in ('ro', 'rw', 'deny', 'nested'):
            path = root / directory
            path.mkdir(exist_ok=True)
            (path / 'file').write_bytes(b'unchanged')
            os.setxattr(path / 'file', 'user.elf_xattr', b'seed')
        (root / 'ro/nested').mkdir(exist_ok=True)
        for path, target in [('ro/to_rw', '/rw/file'), ('rw/to_ro', '/ro/file'),
                             ('rw/dangling', '/rw/absent')]:
            link = root / path
            if link.is_symlink():
                link.unlink()
            link.symlink_to(target)
        guarded = option in ('--guard-path-mutations', '--guard-file-mutations')
        protected = {name: ((root / name / 'file').stat().st_ctime_ns,
                            os.getxattr(root / name / 'file', 'user.elf_xattr'))
                     for name in ('ro', 'deny')}
        subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector', *(['-DGUARDED'] if guarded else []),
                        str(repo / 'test/fs_policy/xattrs.c'), '-o', str(root / 'probe.next')], check=True)
        (root / 'probe.next').replace(root / 'probe')
        command = [str(loader), '--mode', 'container', '--root', str(root),
                   '-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw',
                   '-v', f'{root}/deny:/deny', '-v', f'{root}/nested:/ro/nested',
                   *([option, 'drwdw'] if option else []), '--', './probe']
        p = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=20)
        assert p.returncode == 0, (option, p.returncode, p.stdout, p.stderr)
        for directory in ('ro', 'rw', 'deny', 'nested'):
            assert (root / directory / 'file').read_bytes() == b'unchanged'
        for directory in ('rw', 'nested'):
            assert os.getxattr(root / directory / 'file', 'user.elf_xattr') == b'guest'
        if guarded:
            for directory, expected in protected.items():
                path = root / directory / 'file'
                assert (path.stat().st_ctime_ns, os.getxattr(path, 'user.elf_xattr')) == expected
        assert (root / 'rw/dangling').is_symlink() and not (root / 'rw/absent').exists()
        print('PASS: real xattr paths, links, cwd, nested binds and host state:', option or suffix or 'normal')
