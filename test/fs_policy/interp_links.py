#!/usr/bin/env python3
"""The loader opens PT_INTERP with guest symlink semantics, like PRoot.

The interpreter directory is an absolute symlink inside the rootfs; a
lexical host mapping would follow it to the host's own path instead. A
nested script interpreter is exercised in the same rootfs."""
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
alpine = build / 'alpine-test-root'
interp = 'ld-musl-aarch64.so.1'
if not (alpine / 'bin/busybox').exists() or not (alpine / 'lib' / interp).exists():
    print('SKIP: interpreter link rootfs unavailable:', alpine)
    raise SystemExit(0)

with tempfile.TemporaryDirectory(prefix='interp-links-', dir=build) as tmp:
    root = Path(tmp) / 'root'
    (root / 'bin').mkdir(parents=True)
    (root / 'store/libs').mkdir(parents=True)
    shutil.copy2(alpine / 'bin/busybox', root / 'bin/busybox')
    shutil.copy2(alpine / 'lib' / interp, root / 'store/libs' / interp)
    unique = '/' + Path(tmp).name + '-store'
    assert not Path(unique).exists()
    # /lib -> /<unique>/libs, an absolute link; /<unique> -> store (relative).
    (root / unique.lstrip('/')).symlink_to('store')
    (root / 'lib').symlink_to(unique + '/libs')
    (root / 'bin/sh').symlink_to('/bin/busybox')
    (root / 'wrapper').write_text('#!/bin/sh\necho "wrapped=$0 $*"\n')
    (root / 'tool').write_text('#!/wrapper -x\n')
    (root / 'wrapper').chmod(0o755)
    (root / 'tool').chmod(0o755)
    for suffix, options in (('', []), ('-fd-experiment', []),
                            ('-fd-experiment', ['--guard-file-access', 'r', '--allow-stdio-output',
                                                '--allow-pipe-output'])):
        loader = build / f'elfloader-proot{suffix}'
        manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
        assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root), *options, '--',
                            './bin/busybox', 'sh', '-c', 'echo direct=ok; /bin/busybox echo exec=ok; /tool a; '
                            # The kernel bounds argv by bytes, not count.
                            'echo "many=$(/bin/busybox sh -c \'echo $#\' x $(/bin/busybox seq 1 5000))"'],
                           cwd=root, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, (suffix, options, p.stdout, p.stderr[-1500:])
        lines = [line for line in p.stdout.splitlines() if '=' in line]
        assert lines == ['direct=ok', 'exec=ok', 'wrapped=/wrapper -x /tool a', 'many=5000'], (suffix, lines)
        print('PASS: PT_INTERP through an absolute rootfs link and nested scripts:', loader.name,
              'guarded' if options else 'plain')
