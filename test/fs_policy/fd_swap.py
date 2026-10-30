#!/usr/bin/env python3
"""An FD-based mutation acts on the object its check admitted.

One thread keeps setting times through a number (futimens: no write access
mode needed); another keeps replacing that number with dup3, alternating
between a file in a read-write mount and one in a read-only mount. The
read-only file's times must never change: a swap between the check and the
kernel call would apply the read-write file's admission to it."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']

GUEST = r'''
import os, sys, threading, time
rw = os.open(sys.argv[1], os.O_RDONLY)
ro = os.open(sys.argv[2], os.O_RDONLY)
before = os.stat(sys.argv[2]).st_mtime_ns
target = os.dup(rw)
stop, done, denied = False, [0], [0]
def swap():
    while not stop:
        os.dup2(ro, target)
        os.dup2(rw, target)
def touch():
    while not stop:
        try:
            os.utime(target, ns=(10**15, 10**15))
            done[0] += 1
        except OSError as e:
            assert e.errno in (1, 13, 30), e  # EPERM/EACCES/EROFS: the read-only mount.
            denied[0] += 1
threads = [threading.Thread(target=swap), threading.Thread(target=touch)]
for t in threads: t.start()
time.sleep(6)
stop = True
for t in threads: t.join()
print("applied", done[0], "denied", denied[0])
assert done[0] and denied[0], (done, denied)
assert os.stat(sys.argv[2]).st_mtime_ns == before, "read-only file changed"
'''

with tempfile.TemporaryDirectory(prefix='fd-swap-', dir=build) as tmp:
    root = Path(tmp)
    (root / 'rw').mkdir()
    (root / 'ro').mkdir()
    (root / 'rw/file').write_text('rw')
    (root / 'ro/file').write_text('ro')
    python = str(Path(sys.executable).resolve())
    p = subprocess.run([str(loader), '--mode', 'container', '--root', '/',
                        '-v', f'{root}/rw:/swap-rw', '-v', f'{root}/ro:/swap-ro',
                        '--guard-file-mutations', 'rwr',
                        '--allow-stdio-output', '--allow-pipe-output', '--',
                        python.lstrip('/'), '-B', '-c', GUEST, '/swap-rw/file', '/swap-ro/file'],
                       cwd='/', capture_output=True, text=True, timeout=120)
    errors = [l for l in p.stderr.splitlines() if 'HiLogBase' not in l]
    assert p.returncode == 0, (p.returncode, p.stdout, errors[-15:])
    print('PASS: FD mutations act on the admitted object while the number is swapped:',
          p.stdout.strip().splitlines()[-1])
