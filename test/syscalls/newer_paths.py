#!/usr/bin/env python3
"""Untranslated newer path calls (setxattrat..file_setattr) report ENOSYS.

A raw pass would resolve the guest path on the host; an older kernel's
ENOSYS makes callers fall back to the translated calls. Both builds."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'

GUEST = r'''
import ctypes, errno
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
buffer = ctypes.create_string_buffer(64)
results = []
for number in range(463, 470):
    ctypes.set_errno(0)
    rc = libc.syscall(ctypes.c_long(number), ctypes.c_long(-100), b"/", ctypes.c_long(0),
                      buffer, ctypes.c_long(0), ctypes.c_long(0))
    results.append((number, rc, ctypes.get_errno()))
print(results)
assert all(rc == -1 and err == errno.ENOSYS for _, rc, err in results), results
print("newer-paths=enosys")
'''

try:
    import ctypes  # noqa: F401
except ImportError:
    print('SKIP: ctypes unavailable')
    raise SystemExit(0)
python = str(Path(sys.executable).resolve())
for suffix in ('', '-fd-experiment'):
    loader = build / f'elfloader-proot{suffix}'
    manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
    assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
    p = subprocess.run([str(loader), '--mode', 'container', '--root', '/', '--',
                        python.lstrip('/'), '-B', '-c', GUEST],
                       cwd='/', capture_output=True, text=True, timeout=120)
    assert p.returncode == 0 and 'newer-paths=enosys' in p.stdout, (
        suffix, p.returncode, p.stdout, p.stderr[-2000:])
    print('PASS: newer path calls report ENOSYS:', loader.name)
