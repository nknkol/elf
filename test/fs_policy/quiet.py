#!/usr/bin/env python3
"""The loader leaves no trace in the guest: no extra descriptors, no stderr.

Like PRoot, a guest (and every exec'd child) sees only the descriptors it
was given, and loader diagnostics stay off its stderr unless logging was
requested. Both builds."""
import hashlib
import json
import subprocess
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: rootfs unavailable:', alpine)
    raise SystemExit(0)
# ls holds the listed directory on fd 3; nothing else may be open.
SCRIPT = 'echo $(ls /proc/self/fd); echo $(/bin/busybox ls /proc/self/fd)'
for suffix in ('', '-fd-experiment'):
    loader = build / f'elfloader-proot{suffix}'
    manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
    assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                        '-v', '/proc:/proc', '--', './bin/busybox', 'sh', '-c', SCRIPT],
                       cwd=alpine, capture_output=True, text=True, timeout=60,
                       stdin=subprocess.DEVNULL)
    assert p.returncode == 0, (suffix, p.stdout, p.stderr[-1500:])
    assert p.stdout.splitlines() == ['0 1 2 3', '0 1 2 3'], (suffix, p.stdout)
    assert p.stderr == '', (suffix, p.stderr[:800])
    # Host bind sources are normalized: ".." used to fail every access below.
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                        '-v', f'{alpine}/../{alpine.name}/./etc:/dotdot', '--', './bin/busybox',
                        'cat', '/dotdot/alpine-release'],
                       cwd=alpine, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and p.stdout.strip(), (suffix, p.stdout, p.stderr[-500:])
    print('PASS: no loader descriptors or diagnostics reach the guest:', loader.name)
