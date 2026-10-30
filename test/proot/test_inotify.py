#!/usr/bin/env python3
"""Native/loader watch targets with private roots and external bind fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
parser = argparse.ArgumentParser()
parser.add_argument('--guarded', action='store_true')
args = parser.parse_args()
here = Path(__file__).resolve().parent
build = lib.BUILD
suffix = '-guarded' if args.guarded else ''
loader = lib.loader(suffix)
cases = [('absolute', 'f', '/file', '/file'),
         ('relative', 'f', 'file', 'file'),
         ('bind', 'f', '/mnt/file', '/mnt/file'),
         ('bind-relative', 'f', 'mnt/file', 'mnt/file'),
         ('absolute-symlink', 'f', '/link', '/file'),
         ('cross-bind-symlink', 'f', '/cross', '/mnt/file'),
         ('nofollow', 'n', '/link', '/file'),
         ('bind-nofollow', 'n', '/mnt/link', '/mnt/file'),
         ('directory', 'd', '/mnt', '/mnt/file'),
         ('onlydir-file', 'e', '/mnt/file', '/mnt/file'),
         ('missing', 'm', '/missing', '/file'),
         ('empty', 'x', '', '/file'),
         ('null', 'z', '/file', '/file')]
with tempfile.TemporaryDirectory(prefix='inotify-', dir=build) as temp:
    work = Path(temp)
    probe = work / 'probe'
    subprocess.run(['clang', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-O1', str(here / 'svc_inotify_probe.c'),
                    '-o', str(probe)], check=True)
    for name, mode, watch, target in cases:
        outcomes = []
        for backend in ('native', 'loader'):
            root = work / (name + '-' + backend)
            bound = work / (name + '-' + backend + '-external')
            root.mkdir(); bound.mkdir(); (root / 'mnt').mkdir()
            (root / 'file').write_text('R'); (bound / 'file').write_text('B')
            def host(path):
                if not path:
                    return ''
                relative = path.lstrip('/')
                return str(bound / relative[4:]) if relative.startswith('mnt/') else str(bound if relative == 'mnt' else root / relative)
            (root / 'link').symlink_to(host('/file') if backend == 'native' else '/file')
            (root / 'cross').symlink_to(host('/mnt/file') if backend == 'native' else '/mnt/file')
            (bound / 'link').symlink_to('file')
            if backend == 'native':
                command = [str(probe), mode, host(watch), host(target)]
            else:
                (root / 'probe').write_bytes(probe.read_bytes()); (root / 'probe').chmod(0o755)
                command = [str(loader), '--mode', 'container', '--root', str(root),
                           '-v', f'{bound}:/mnt', '--', './probe', mode, watch, target]
            result = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=15)
            assert result.returncode == 0 and 'PASS:' in result.stdout, (name, backend, result.returncode, result.stdout, result.stderr)
            outcomes.append(result.stdout)
        assert outcomes[0] == outcomes[1], (name, outcomes)
        print('PASS: inotify', name, outcomes[0].strip())
    # Host source spelling must not bypass the guest root, even when it exists.
    result = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                             '-v', f'{bound}:/mnt', '--', './probe', 'm',
                             str(bound / 'file'), '/file'], cwd=root,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0 and 'PASS:' in result.stdout, (result.returncode, result.stdout, result.stderr)
    print('PASS: inotify rejects unmapped host-source spelling')
print(len(cases), 'native/loader inotify path comparisons passed', suffix)
