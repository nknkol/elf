#!/usr/bin/env python3
"""Fake root identity is consistent: ids and the caller's file owners read 0."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: identity rootfs unavailable:', alpine)
    raise SystemExit(0)
SCRIPT = ('echo "ids=$(id -u):$(id -g)"; echo "etc=$(stat -c %u:%g /etc/hostname)"; '
          'echo "self=$(stat -L -c %u:%g /proc/self/fd/0 < /etc/hostname)"; '
          'echo "new=$(touch /work/made && stat -c %u:%g /work/made)"')
# The rootfs is the caller's tree (on some backings owned by a service uid).
assert os.stat(alpine / 'etc/hostname').st_uid == os.stat(alpine).st_uid
for suffix in ('', '-guarded'):
    loader = lib.loader(suffix)
    work = build / f'ids-work{suffix}'
    work.mkdir(exist_ok=True)
    try:
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                            '-v', '/proc:/proc', '-v', f'{work}:/work', '--', './bin/busybox',
                            'sh', '-c', SCRIPT], cwd=alpine, capture_output=True, text=True,
                           timeout=60)
    finally:
        (work / 'made').unlink(missing_ok=True)
        work.rmdir()
    assert p.returncode == 0, (suffix, p.stdout, p.stderr[-1500:])
    values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    assert values == {'ids': '0:0', 'etc': '0:0', 'self': '0:0', 'new': '0:0'}, (suffix, values)
    print('PASS: fake root ids and caller-owned stat owners:', 'elfloader' + suffix)
