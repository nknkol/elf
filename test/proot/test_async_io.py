#!/usr/bin/env python3
"""Signal-driven I/O settings (async_io.h): HarmonyOS refuses FIOASYNC,
O_ASYNC and F_SETOWN on sockets (natively too: ENOTTY, EINVAL), which
stopped nginx from starting its workers.

Expected, both builds, plain and with --isolate: on a socketpair end,
FIOASYNC, F_SETOWN, F_SETSIG and F_SETFL with O_ASYNC succeed and F_GETOWN,
F_GETSIG and F_GETFL read them back; a socket that later gets the same FD
number has none of them; a pipe keeps the kernel's own O_ASYNC. (No SIGIO
is sent for an emulated setting: STATUS.md.) Natively the socket calls
fail, which is checked first."""
import json
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

GUEST = r'''
import fcntl, json, os, socket, struct
F_SETSIG, F_GETSIG = 10, 11
out = {}
def attempt(name, f):
    try:
        out[name] = f()
    except OSError as e:
        out[name] = -e.errno
a, b = socket.socketpair()
fd = a.fileno()
attempt('fioasync', lambda: fcntl.ioctl(fd, 0x5452, struct.pack('i', 1)) and 0)
attempt('setown', lambda: fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid()))
attempt('getown', lambda: fcntl.fcntl(fd, fcntl.F_GETOWN) == os.getpid())
attempt('setsig', lambda: fcntl.fcntl(fd, F_SETSIG, 29))
attempt('getsig', lambda: fcntl.fcntl(fd, F_GETSIG))
attempt('setfl', lambda: fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_ASYNC))
attempt('getfl', lambda: bool(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ASYNC))
a.close(); b.close()
c, d = socket.socketpair()
attempt('reused', lambda: [c.fileno() == fd, bool(fcntl.fcntl(c.fileno(), fcntl.F_GETFL) & os.O_ASYNC)])
r, w = os.pipe()
attempt('pipe', lambda: [fcntl.fcntl(r, fcntl.F_SETFL, fcntl.fcntl(r, fcntl.F_GETFL) | os.O_ASYNC),
                         bool(fcntl.fcntl(r, fcntl.F_GETFL) & os.O_ASYNC)])
print('RESULT ' + json.dumps(out))
'''
python = str(Path(sys.executable).resolve())


def result(argv):
    p = subprocess.run(argv, cwd='/', capture_output=True, text=True, timeout=60)
    lines = [line for line in p.stdout.splitlines() if line.startswith('RESULT ')]
    assert p.returncode == 0 and lines, (argv[:3], p.returncode, p.stdout[-800:], p.stderr[-800:])
    return json.loads(lines[-1][7:])


native = result([python, '-B', '-c', GUEST])
refused = native['fioasync'] < 0 and native['setown'] < 0
print('native:', 'socket async I/O refused' if refused else 'socket async I/O supported', native)
EXPECTED = {'fioasync': 0, 'setown': 0, 'getown': True, 'setsig': 0, 'getsig': 29, 'setfl': 0,
            'getfl': True, 'reused': [True, False], 'pipe': [0, True]}
for suffix, loader in lib.loaders():
    for isolate in ([], ['--isolate']):
        what = (loader.name, *isolate)
        out = result([str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container', '--root', '/',
                      '--', python.lstrip('/'), '-B', '-c', GUEST])
        assert out == EXPECTED, (what, out)
        print('PASS: signal-driven I/O settings on a socket accepted and read back, dropped with the FD,'
              ' a pipe\'s kept by the kernel:', *what)
