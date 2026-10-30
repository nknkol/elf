#!/usr/bin/env python3
"""Reentry leases do not run out over a large process tree.

The default build shares its reentry table across fork. Each child that
exec'd from inside an intercepted call used to keep its lease forever, so
after 32 such children every intercepted call in the tree failed with
EAGAIN and callers spun (dpkg unpacking packages). The table also spanned
the whole tree, so processes blocked in pipe reads exhausted it. Both builds."""
import hashlib
import json
import subprocess
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: process tree rootfs unavailable:', alpine)
    raise SystemExit(0)

SCRIPT = ('i=0; while [ $i -lt 100 ]; do /bin/busybox true || exit 9; i=$((i+1)); done; '
          'echo "sequential=$(cat /etc/alpine-release | wc -l)"; '
          # 40 exec'd children alive, plus 40 blocked inside read on a pipe.
          'i=0; while [ $i -lt 40 ]; do /bin/busybox sleep 3 & '
          '/bin/busybox sleep 3 | /bin/busybox cat & i=$((i+1)); done; /bin/busybox sleep 1; '
          'echo "concurrent=$(cat /etc/alpine-release | wc -l)"; wait; '
          'echo "after=$(ls /etc/alpine-release)"')
for suffix in ('', '-guarded'):
    loader = lib.loader(suffix)
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine), '--',
                        './bin/busybox', 'sh', '-c', SCRIPT],
                       cwd=alpine, capture_output=True, text=True, timeout=180)
    assert p.returncode == 0, (suffix, p.returncode, p.stdout, p.stderr[-1500:])
    values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    assert values == {'sequential': '1', 'concurrent': '1', 'after': '/etc/alpine-release'}, (
        suffix, values)
    print('PASS: exec children and blocked pipe readers keep leases available:', loader.name)
