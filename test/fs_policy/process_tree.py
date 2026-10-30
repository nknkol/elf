#!/usr/bin/env python3
"""Reentry leases do not run out over a large process tree.

The default build shares its reentry table across fork. Each child that
exec'd from inside an intercepted call used to keep its lease forever, so
after 32 such children every intercepted call in the tree failed with
EAGAIN and callers spun (dpkg unpacking packages). Both builds."""
import hashlib
import json
import subprocess
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: process tree rootfs unavailable:', alpine)
    raise SystemExit(0)

SCRIPT = ('i=0; while [ $i -lt 100 ]; do /bin/busybox true || exit 9; i=$((i+1)); done; '
          'echo "sequential=$(cat /etc/alpine-release | wc -l)"; '
          'i=0; while [ $i -lt 40 ]; do /bin/busybox sleep 3 & i=$((i+1)); done; '
          'echo "concurrent=$(cat /etc/alpine-release | wc -l)"; wait; '
          'echo "after=$(ls /etc/alpine-release)"')
for suffix in ('', '-fd-experiment'):
    loader = build / f'elfloader-proot{suffix}'
    manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
    assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine), '--',
                        './bin/busybox', 'sh', '-c', SCRIPT],
                       cwd=alpine, capture_output=True, text=True, timeout=180)
    assert p.returncode == 0, (suffix, p.returncode, p.stdout, p.stderr[-1500:])
    values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    assert values == {'sequential': '1', 'concurrent': '1', 'after': '/etc/alpine-release'}, (
        suffix, values)
    print('PASS: 100 sequential and 40 concurrent exec children keep leases available:', loader.name)
