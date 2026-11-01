#!/usr/bin/env python3
"""Mounts inside a container (docs/OCI.md, R4): with --emulate-mounts the
guest's mount(2) and umount2(2) change a mount table every process of the
view shares; nothing is mounted in the kernel.

Expected: bind mounts (also recursive, read-only in the guarded build),
tmpfs (an empty directory of its own, mode from the options), proc from
the host, MS_MOVE and stacking behave as in a mount namespace; a mount made
by one process is seen by its children (across exec, after closefrom) and
its parent; /proc/self/mounts and mountinfo list the table; unsupported
types give ENODEV, umount of a non-mountpoint EINVAL; the new mount API
gives ENOSYS (util-linux falls back to mount(2)). Without the option mount
stays unavailable. Both builds, plain and with --isolate."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

GUEST = r'''
import ctypes, errno, json, os, subprocess, sys
libc = ctypes.CDLL(None, use_errno=True)
MS_RDONLY, MS_REMOUNT, MS_BIND, MS_MOVE, MS_REC, MS_PRIVATE = 1, 32, 4096, 8192, 16384, 1 << 18
def mount(src, dst, fstype, flags=0, data=None):
    enc = lambda s: s.encode() if s is not None else None
    rc = libc.mount(enc(src), enc(dst), enc(fstype), ctypes.c_ulong(flags), enc(data))
    return 0 if rc == 0 else errno.errorcode[ctypes.get_errno()]
def umount(dst, flags=0):
    rc = libc.umount2(dst.encode(), flags)
    return 0 if rc == 0 else errno.errorcode[ctypes.get_errno()]
def names(d):
    try:
        return sorted(os.listdir(d))
    except OSError as e:
        return errno.errorcode[e.errno]
def table():
    with open('/proc/self/mounts') as f:
        return [line.split()[:3] for line in f if line.split()[1].startswith('/w/')]
out = {}
out['bind'] = mount('/w/a', '/w/b', None, MS_BIND)
out['bind_names'] = names('/w/b')
open('/w/b/new', 'w').write('x')
out['bind_write_host'] = os.path.exists('/w/a/new')
out['table'] = table()
out['proc_mounts'] = [line.split()[1] for line in open('/proc/mounts') if line.split()[1].startswith('/w/')]
with open('/proc/self/mountinfo') as f:
    out['mountinfo'] = [l.split()[4] for l in f if ' /w/b ' in l]
# A child (subprocess closes FDs above 2 before exec) sees the mount and
# makes one its parent sees.
r = subprocess.run([sys.executable, '-B', '-c',
    'import os, ctypes; l = ctypes.CDLL(None); print(sorted(os.listdir("/w/b")), '
    'l.mount(b"none", b"/w/t", b"tmpfs", 0, b"mode=0750"))'],
    capture_output=True, text=True)
out['child'] = r.stdout.strip()
out['tmpfs_names'] = names('/w/t')
out['tmpfs_mode'] = oct(os.stat('/w/t').st_mode & 0o7777)
open('/w/t/scratch', 'w').write('y')
out['tmpfs_hides_host'] = os.path.exists('/w/t-host-file') and not os.path.exists('/w/t/t-host-file')
# Stacking: a second tmpfs hides the first until it goes.
out['stack'] = [mount('none', '/w/t', 'tmpfs'), names('/w/t'), umount('/w/t'), names('/w/t')]
out['umount_tmpfs'] = [umount('/w/t'), names('/w/t')]
out['proc'] = [mount('proc', '/w/p', 'proc'), os.path.exists('/w/p/self/status')]
out['move'] = [mount('/w/p', '/w/m', None, MS_MOVE), os.path.exists('/w/m/self/status'),
               names('/w/p')]
# --rbind: the mounts below the source appear below the target.
out['rbind'] = [mount('none', '/w/a/sub', 'tmpfs'), mount('/w/a', '/w/r', None, MS_BIND | MS_REC),
                names('/w/r'), names('/w/r/sub')]
out['busy'] = umount('/w/r')
out['detach'] = [umount('/w/r', 2), names('/w/r')]
out['errors'] = [mount('/dev/sda1', '/w/x', 'ext4'), mount('none', '/w/x', 'overlay'),
                 umount('/w/x'), umount('/w/a/sub'), umount('/w/a/sub'),
                 mount('none', '/w/missing', 'tmpfs'), mount(None, '/', None, MS_REC | MS_PRIVATE)]
out['fsopen'] = errno.errorcode[ctypes.get_errno()] if libc.syscall(430, b"tmpfs", 0) < 0 else 'ok'
out['umount_bind'] = [umount('/w/b'), names('/w/b')]
# A read-only bind: refused writes where the build enforces mount access.
out['ro'] = [mount('/w/a', '/w/b', None, MS_BIND),
             mount(None, '/w/b', None, MS_BIND | MS_REMOUNT | MS_RDONLY)]
try:
    open('/w/b/ro-test', 'w').close()
    out['ro'].append('written')
except OSError as e:
    out['ro'].append(errno.errorcode[e.errno])
out['ro'].append([line.split()[3].split(',')[0] for line in open('/proc/self/mounts')
                  if line.split()[1] == '/w/b'])
out['left'] = [umount('/w/b'), umount('/w/m')]
print('RESULT ' + json.dumps(out))
'''

python = Path(sys.executable).resolve()
with tempfile.TemporaryDirectory(prefix='mounts-', dir=lib.mode_capable()) as tmp:
    for suffix, loader in lib.loaders():
        for isolate in ([], ['--isolate']):
            work = Path(tmp, 'w' + suffix + ''.join(isolate))
            for d in ('a', 'b', 't', 'p', 'm', 'r', 'x', 'a/sub'):
                (work / d).mkdir(parents=True)
            (work / 'a' / 'from-a').write_text('a')
            (work / 'b' / 'from-b').write_text('b')
            (work / 't' / 't-host-file').write_text('t')
            (work / 't-host-file').write_text('t')
            scratch = Path(tmp, 'scratch' + suffix + ''.join(isolate))
            guard = ['--guard-path-mutations', 'ww'] if suffix else []
            common = [str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container', '--root', '/',
                      '-v', f'{work}:/w', *guard]
            p = subprocess.run([*common, '--emulate-mounts', '--mount-scratch', str(scratch),
                                '--', str(python).lstrip('/'), '-B', '-c', GUEST],
                               cwd='/', capture_output=True, text=True, timeout=180)
            lines = [line for line in p.stdout.splitlines() if line.startswith('RESULT ')]
            assert p.returncode == 0 and lines, (suffix, isolate, p.returncode, p.stdout[-2000:],
                                                 p.stderr[-3000:])
            out = json.loads(lines[-1][7:])
            what = (loader.name, isolate)
            assert out['bind'] == 0 and out['bind_names'] == ['from-a', 'sub'], (what, out)
            assert out['bind_write_host'], (what, out)
            assert [row[1] for row in out['table']] == ['/w/b'], (what, out['table'])
            assert out['mountinfo'] == ['/w/b'] and out['proc_mounts'] == ['/w/b'], (what, out)
            assert out['child'] == "['from-a', 'new', 'sub'] 0", (what, out['child'])
            assert out['tmpfs_names'] == [] and out['tmpfs_mode'] == '0o750', (what, out)
            assert out['tmpfs_hides_host'], (what, out)
            assert out['stack'] == [0, [], 0, ['scratch']], (what, out['stack'])
            assert out['umount_tmpfs'] == [0, ['t-host-file']], (what, out['umount_tmpfs'])
            assert out['proc'] == [0, True], (what, out['proc'])
            assert out['move'] == [0, True, []], (what, out['move'])
            assert out['rbind'] == [0, 0, ['from-a', 'new', 'sub'], []], (what, out['rbind'])
            assert out['busy'] == 'EBUSY' and out['detach'] == [0, []], (what, out)
            assert out['errors'] == ['ENODEV', 'ENODEV', 'EINVAL', 0, 'EINVAL', 'ENOENT', 0], \
                (what, out['errors'])
            assert out['fsopen'] == 'ENOSYS', (what, out['fsopen'])
            assert out['umount_bind'] == [0, ['from-b']], (what, out['umount_bind'])
            expected_ro = [0, 0, 'EROFS' if suffix else 'written', ['ro']]
            assert out['ro'] == expected_ro, (what, out['ro'])
            assert out['left'] == [0, 0], (what, out['left'])
            # The host saw nothing mounted: b still holds only its own file
            # (plus what the guest wrote through the read-write bind).
            assert sorted(os.listdir(work / 'b')) == ['from-b'], (what, os.listdir(work / 'b'))
            # Without --emulate-mounts mount stays unavailable.
            p = subprocess.run([*common, '--', str(python).lstrip('/'), '-B', '-c',
                                'import ctypes; l = ctypes.CDLL(None, use_errno=True); '
                                'print(l.mount(b"/w/a", b"/w/b", None, 4096, None), ctypes.get_errno())'],
                               cwd='/', capture_output=True, text=True, timeout=60)
            assert p.returncode == 0 and p.stdout.split()[0] == '-1', (what, p.stdout, p.stderr[-1000:])
            print('PASS: emulated mounts (bind, rbind, tmpfs, proc, move, stack, ro, /proc tables):',
                  loader.name, *isolate)
