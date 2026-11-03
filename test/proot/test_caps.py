#!/usr/bin/env python3
"""Capabilities of the fake ids (fake_ids.c): what Linux gives these ids,
out of Docker's default set (CapEff 00000000a80425fb).

Expected, both builds, plain and with --isolate:
- root: capget shows the default set in the effective and permitted sets;
  the bounding set holds CAP_CHOWN, not CAP_NET_ADMIN;
- util-linux setpriv --reuid --regid (redis's entrypoint): with
  PR_SET_KEEPCAPS, setresuid(999, 999, -1) empties the effective set and
  keeps the permitted one, so setresgid is refused until capset raises
  CAP_SETGID again, then it works;
- all uids nonzero without PR_SET_KEEPCAPS: both sets empty, capset cannot
  raise anything, setuid(0) is refused;
- euid back to 0 (saved uid 0): the permitted set is effective again;
- capset beyond the permitted set: EPERM."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

GUEST = r'''
import ctypes, errno, json, os, sys
libc = ctypes.CDLL(None, use_errno=True)
class Header(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
class Data(ctypes.Structure):
    _fields_ = [('eff', ctypes.c_uint32), ('prm', ctypes.c_uint32), ('inh', ctypes.c_uint32)]
V3 = 0x20080522
def caps():
    h, d = Header(V3, 0), (Data * 2)()
    rc = libc.capget(ctypes.byref(h), d)
    return [rc, hex(d[0].eff | d[1].eff << 32), hex(d[0].prm | d[1].prm << 32)]
def capset(eff, prm):
    h, d = Header(V3, 0), (Data * 2)()
    d[0].eff, d[1].eff, d[0].prm, d[1].prm = eff & 0xffffffff, eff >> 32, prm & 0xffffffff, prm >> 32
    return 0 if libc.capset(ctypes.byref(h), d) == 0 else -ctypes.get_errno()
def call(f, *a):
    try:
        f(*a); return 0
    except OSError as e:
        return -e.errno
out = {}
mode = sys.argv[1]
if mode == 'root':
    out['caps'] = caps()
    out['bnd'] = [libc.prctl(23, 0, 0, 0, 0), libc.prctl(23, 12, 0, 0, 0)]
elif mode == 'setpriv':
    out['keep'] = libc.prctl(8, 1, 0, 0, 0)
    out['setresuid'] = call(os.setresuid, 999, 999, -1)
    out['after_uid'] = caps()
    out['gid_refused'] = call(os.setresgid, 1000, 1000, -1)
    prm = int(caps()[2], 16)
    out['raise'] = capset(1 << 6, prm)
    out['setresgid'] = call(os.setresgid, 1000, 1000, -1)
    out['ids'] = [list(os.getresuid()), list(os.getresgid())]
elif mode == 'drop':
    out['setresuid'] = call(os.setresuid, 999, 999, 999)
    out['caps'] = caps()
    out['raise'] = capset(1 << 6, 1 << 6)
    out['setuid0'] = call(os.setuid, 0)
elif mode == 'back':
    out['setresuid'] = call(os.setresuid, 999, 999, -1)
    out['away'] = caps()
    out['seteuid0'] = call(os.setresuid, -1, 0, -1)
    out['back'] = caps()
    out['beyond'] = capset(1 << 21, int(caps()[2], 16) | 1 << 21)
print('RESULT ' + json.dumps(out))
'''
DEFAULT = '0xa80425fb'
python = str(Path(sys.executable).resolve()).lstrip('/')

for suffix, loader in lib.loaders():
    for isolate in ([], ['--isolate']):
        what = (loader.name, *isolate)

        def run(mode):
            p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container', '--root', '/',
                                '--', python, '-B', '-c', GUEST, mode], cwd='/', capture_output=True, text=True,
                               timeout=60)
            lines = [line for line in p.stdout.splitlines() if line.startswith('RESULT ')]
            assert p.returncode == 0 and lines, (what, mode, p.returncode, p.stdout[-1500:], p.stderr[-1500:])
            return json.loads(lines[-1][7:])
        out = run('root')
        assert out == {'caps': [0, DEFAULT, DEFAULT], 'bnd': [1, 0]}, (what, out)
        out = run('setpriv')
        assert out == {'keep': 0, 'setresuid': 0, 'after_uid': [0, '0x0', DEFAULT], 'gid_refused': -1,
                       'raise': 0, 'setresgid': 0, 'ids': [[999, 999, 0], [1000, 1000, 0]]}, (what, out)
        out = run('drop')
        assert out == {'setresuid': 0, 'caps': [0, '0x0', '0x0'], 'raise': -1, 'setuid0': -1}, (what, out)
        out = run('back')
        assert out == {'setresuid': 0, 'away': [0, '0x0', DEFAULT], 'seteuid0': 0,
                       'back': [0, DEFAULT, DEFAULT], 'beyond': -1}, (what, out)
        print('PASS: capabilities of the fake ids (Docker default set, setpriv with PR_SET_KEEPCAPS,'
              ' all uids dropped, euid back to 0, capset limits):', *what)
