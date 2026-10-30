#!/usr/bin/env python3
"""A dup racing a close/reopen of its source never copies the wrong origin.

One thread keeps replacing a number between a recorded unknown-origin
object (opened relative to the unknown initial cwd) and a freshly opened
read-write file; another dups that
number. The copy's recorded origin must belong to the object the kernel
actually copied: a copy of the unknown object must never carry the new
object's read-write grant."""
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
import ctypes, os, sys, threading
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
QUERY, ACCESS, UNKNOWN = 0x46445452, 5, 0
def access(fd):
    return libc.syscall(ctypes.c_long(167), ctypes.c_long(QUERY), ctypes.c_long(ACCESS),
                        ctypes.c_long(fd), ctypes.c_long(0), ctypes.c_long(0))
inherited = os.open(sys.argv[2], os.O_RDONLY)  # Unknown cwd: recorded, origin unknown.
assert access(inherited) == UNKNOWN, access(inherited)
unknown_ino = os.fstat(inherited).st_ino
src = os.dup(inherited)
stop, bad, copies = False, [], [0]
def flip():
    while not stop:
        os.close(src)
        fd = os.open(sys.argv[1], os.O_RDWR)  # Lowest free number: src again.
        if fd != src:
            os.dup2(fd, src); os.close(fd)
        os.dup2(inherited, src)               # Back to the unknown object.
def copy():
    while not stop:
        try:
            d = os.dup(src)
        except OSError:
            continue
        if os.fstat(d).st_ino == unknown_ino and access(d) != UNKNOWN:
            bad.append(d)
        copies[0] += 1
        os.close(d)
threads = [threading.Thread(target=flip), threading.Thread(target=copy)]
for t in threads: t.start()
import time; time.sleep(8)
stop = True
for t in threads: t.join()
print("copies", copies[0], "bad", len(bad))
assert not bad
'''

with tempfile.TemporaryDirectory(prefix='dup-race-', dir=build) as tmp:
    root = Path(tmp)
    (root / 'rw').mkdir()
    (root / 'rw/file').write_text('rw')
    (root / 'rw/unknown').write_text('unknown')
    python = str(Path(sys.executable).resolve())
    p = subprocess.run([str(loader), '--mode', 'container', '--root', '/',
                        '-v', f'{root}/rw:/dup-rw', '--guard-file-mutations', 'rw',
                        '--allow-stdio-output', '--allow-pipe-output', '--',
                        python.lstrip('/'), '-B', '-c', GUEST, '/dup-rw/file', 'dup-rw/unknown'],
                       cwd='/', capture_output=True, text=True, timeout=120)
    errors = [l for l in p.stderr.splitlines() if 'HiLogBase' not in l]
    assert p.returncode == 0, (p.returncode, p.stdout, errors[-15:])
    print('PASS: concurrent dup and source reuse keep the copied object\'s origin:',
          p.stdout.strip().splitlines()[-1])
