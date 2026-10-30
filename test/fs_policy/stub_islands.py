#!/usr/bin/env python3
"""Every guest svc is hooked, from a few stub islands. Both builds.

The guest (host python under the loader, root "/") scans its own anonymous
executable memory: no raw `svc #0` may remain outside the payload (which
issues the real calls; it carries the "HOOK" magic) and the stub islands
(whose only svc is each stub's rt_sigreturn path), and stubs come in
islands next to the code rather than one page per site."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'

GUEST = r'''
import ctypes, struct
regions = left = 0
for line in open("/proc/self/maps").read().splitlines():
    p = line.split(); name = p[5] if len(p) > 5 else ""
    if "x" not in p[1] or "r" not in p[1] or name: continue
    lo, hi = (int(x, 16) for x in p[0].split("-")); regions += 1
    w = struct.unpack("<%dI" % ((hi - lo) // 4), ctypes.string_at(lo, hi - lo))
    if 0x484F4F4B in w: continue                     # The payload ("HOOK" magic).
    if w[0] == 0xd503245f and w[1] == 0x71022d1f:     # A stub island (bti c; cmp w8):
        continue                                      # its svc is the rt_sigreturn path.
    left += sum(1 for x in w if x == 0xd4000001)
print("regions", regions, "unpatched", left)
# Islands and the payload are sealed against the guest's own mm calls.
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
island = payload = None
for line in open("/proc/self/maps").read().splitlines():
    p = line.split(); name = p[5] if len(p) > 5 else ""
    if "x" not in p[1] or name: continue
    lo, hi = (int(x, 16) for x in p[0].split("-"))
    w = struct.unpack("<%dI" % ((hi - lo) // 4), ctypes.string_at(lo, hi - lo))
    if 0x484F4F4B in w: payload = lo
    elif w[0] == 0xd503245f and w[1] == 0x71022d1f: island = lo
calls = [libc.munmap(ctypes.c_void_p(island), 4096), libc.mprotect(ctypes.c_void_p(island), 4096, 3),
         libc.madvise(ctypes.c_void_p(island), 4096, 4), libc.munmap(ctypes.c_void_p(payload), 4096)]
errors = [ctypes.get_errno()]
fixed = libc.mmap(ctypes.c_void_p(island), 4096, 3, 0x32, -1, 0)
print("sealed", calls, errors, fixed == ctypes.c_void_p(-1).value, ctypes.get_errno(), open("/proc/self/comm").read().strip())
'''
python = str(Path(sys.executable).resolve())
for suffix in ('', '-fd-experiment'):
    loader = build / f'elfloader-proot{suffix}'
    manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
    assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
    p = subprocess.run([str(loader), '--mode', 'container', '--root', '/', '--',
                        python.lstrip('/'), '-B', '-c', 'import ctypes, ssl, sqlite3\n' + GUEST],
                       cwd='/', capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, (suffix, p.stdout, p.stderr[-1500:])
    regions, left = (int(x) for x in p.stdout.split()[1:4:2])
    sealed = p.stdout.splitlines()[1]
    # munmap/mprotect/madvise/munmap(payload) fail with EPERM; MAP_FIXED too;
    # and the process keeps working (the open above still ran).
    assert sealed.startswith('sealed [-1, -1, -1, -1] [1] True 1 '), sealed
    assert left == 0, p.stdout
    # Code plus at most two islands per executable segment, not a page per svc.
    assert regions < 100, p.stdout
    print(f'PASS: all guest syscalls hooked from {regions} executable regions:', loader.name)

# Section headers do not limit control flow: code outside SHF_EXECINSTR
# sections but inside an executable mapping must still be intercepted
# (scanned whole without the backstop, trapped with it). Only with the
# backstop may scanning skip non-code sections, leaving literal data alone.
alpine = build / 'alpine-test-root'
if (alpine / 'bin/busybox').exists():
    release = (alpine / 'etc/alpine-release').read_text().strip()
    with tempfile.TemporaryDirectory(prefix='code-only-', dir=build) as tmp:
        probe = Path(tmp) / 'probe'
        subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                        '-fno-stack-protector', '-Wl,-e,_start', '-Wl,--no-rosegment',
                        str(repo / 'test/fs_policy/code_only_probe.c'), '-o', str(probe)], check=True)
        for suffix in ('', '-fd-experiment'):
            loader = build / f'elfloader-proot{suffix}'
            for options, literal in (([], 'literal=patched'), (['--seccomp-backstop'], 'literal=intact')):
                p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine), *options,
                                    '-v', f'{tmp}:/work', '--', './bin/busybox', 'sh', '-c',
                                    'exec /work/probe'],
                                   cwd=alpine, capture_output=True, text=True, timeout=60)
                assert p.returncode == 0, (suffix, options, p.stdout, p.stderr[-800:])
                assert p.stdout.split() == [literal, f'open={release}'], (suffix, options, p.stdout)
            print('PASS: svc outside code sections is intercepted; literals kept only with backstop:',
                  loader.name)
