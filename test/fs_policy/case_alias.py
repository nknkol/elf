#!/usr/bin/env python3
"""A nested mount's policy cannot be bypassed by a case alias.

Mounts are chosen by exact guest names. On host storage that matches names
regardless of case (hmdfs, sharefs), /work/secret would resolve through
the read-write /work mount to the very directory the denied /work/Secret
mount covers. The loader marks such mountpoints and path walking spells
their case variants exactly, so the nested policy applies to every
spelling; equal policies, and case-sensitive storage, behave as before."""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
loader = build / 'elfloader-guarded'
alpine = build / 'alpine-test-root'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elfloader-guarded.json').read_text())['sha256']
if not (alpine / 'bin/busybox').exists():
    print('SKIP: rootfs unavailable:', alpine)
    raise SystemExit(0)

with tempfile.TemporaryDirectory(prefix='case-alias-', dir=build) as tmp:
    work = Path(tmp) / 'work'
    (work / 'Secret').mkdir(parents=True)
    (work / 'Secret/key').write_text('secret')
    insensitive = (work / 'secret').exists() and os.path.samefile(work / 'secret', work / 'Secret')

    def run(policy):
        script = ('for p in /work/Secret /work/secret /work/SECRET /work/sEcReT; do '
                  './bin/busybox cat $p/key ; echo " $?"; done')
        return subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                               '-v', f'{work}:/work', '-v', f'{work}/Secret:/work/Secret',
                               '--guard-file-access', policy, '--allow-stdio-output', '--',
                               './bin/busybox', 'sh', '-c', script],
                              cwd=alpine, capture_output=True, text=True, timeout=60)
    denied = run('rwd')
    assert denied.returncode == 0 and 'secret' not in denied.stdout, \
        (denied.returncode, denied.stdout, denied.stderr[-500:])
    same = run('rww')
    expect = ['secret 0'] * 4 if insensitive else ['secret 0', '1', '1', '1']
    assert same.returncode == 0 and [l.strip() for l in same.stdout.splitlines()] == expect, \
        (insensitive, same.returncode, same.stdout, same.stderr[-500:])
    print('PASS: nested mount policy holds for every case spelling; case-insensitive host:',
          insensitive)
