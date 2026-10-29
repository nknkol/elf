#!/usr/bin/env python3
"""Binds below directories missing from the root (PRoot glue), both backends."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: glue rootfs unavailable:', alpine)
    raise SystemExit(0)
assert not (alpine / 'glue').exists()
SCRIPT = ('echo "read=$(cat /glue/deep/w/f)"; echo "type=$(stat -c %F /glue/deep)"; '
          '[ -d /glue ] && echo "dir=yes"; [ -x /glue/deep ] && echo "search=yes"; '
          'echo "rel=$(cd / && cat glue/deep/../deep/w/f)"; '
          'cat /glue/missing 2>/dev/null || echo "other=absent"')
with tempfile.TemporaryDirectory(prefix='glue-', dir=build) as tmp:
    (Path(tmp) / 'f').write_text('bound\n')
    for suffix, options in (('', []), ('-fd-experiment', []),
                            ('-fd-experiment', ['--guard-file-access', 'rr',
                                                '--allow-stdio-output', '--allow-pipe-output',
                                                '--revalidate-file-fds'])):
        loader = build / f'elfloader-proot{suffix}'
        manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
        assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                            '-v', f'{tmp}:/glue/deep/w', *options, '--', './bin/busybox', 'sh',
                            '-c', SCRIPT], cwd=alpine, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, (suffix, options, p.stdout, p.stderr[-1500:])
        values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
        assert values == {'read': 'bound', 'type': 'directory', 'dir': 'yes', 'search': 'yes',
                          'rel': 'bound', 'other': 'absent'}, (suffix, options, values)
        print('PASS: binds below missing directories:', loader.name, 'guarded' if options else 'plain')
    assert not (alpine / 'glue').exists(), 'glue must not create host directories'
