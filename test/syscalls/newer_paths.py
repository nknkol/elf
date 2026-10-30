#!/usr/bin/env python3
"""Untranslated newer path calls (setxattrat..file_setattr) report ENOSYS.

A raw pass would resolve the guest path on the host; an older kernel's
ENOSYS makes callers fall back to the translated calls. Both builds."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD

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
for suffix in ('', '-guarded'):
    loader = lib.loader(suffix)
    p = subprocess.run([str(loader), '--mode', 'container', '--root', '/', '--',
                        python.lstrip('/'), '-B', '-c', GUEST],
                       cwd='/', capture_output=True, text=True, timeout=120)
    assert p.returncode == 0 and 'newer-paths=enosys' in p.stdout, (
        suffix, p.returncode, p.stdout, p.stderr[-2000:])
    print('PASS: newer path calls report ENOSYS:', loader.name)
