#!/usr/bin/env python3
"""The broker does not hold its caller's stdio (docs/OCI.md, "exec"; part
of the application sandbox's acceptance suite). The broker lives as long as
any guest process does; a daemon that let go of its own stdio (setsid,
stdio to /dev/null) kept `docker exec`'s pipe open through the broker's
inherited copy, and the exec never ended.

Expected, both builds: under --isolate, a guest that starts such a daemon
and exits leaves the caller's stdout and stderr pipes at EOF at once while
the daemon still runs; with --log the broker keeps stderr (its log goes
there) and still lets stdout go."""
import os
import select
import subprocess
import sys
import threading
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

python = str(Path(sys.executable).resolve()).lstrip('/')
DAEMON = ('import subprocess, sys\n'
          'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)", "broker-stdio-daemon"],'
          ' start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,'
          ' stderr=subprocess.DEVNULL)\n'
          'print("started", flush=True)\n')


def daemons():
    found = []
    for entry in os.listdir('/proc'):
        if entry.isdigit():
            try:
                if b'broker-stdio-daemon' in Path(f'/proc/{entry}/cmdline').read_bytes():
                    found.append(int(entry))
            except OSError:
                pass
    return found


def eof_after(stream, seconds):
    """Whether stream reaches EOF within seconds (reading what comes)."""
    deadline = time.time() + seconds
    data = b''
    while time.time() < deadline:
        ready, _, _ = select.select([stream], [], [], max(0.0, deadline - time.time()))
        if not ready:
            break
        chunk = os.read(stream.fileno(), 4096)
        if not chunk:
            return True, data
        data += chunk
    return False, data


failures = []
for suffix, loader in lib.loaders():
    for log in ([], ['--log', '4']):
        what = (loader.name, *log)
        p = subprocess.Popen([str(loader), *lib.ISOLATE_EXTRA, '--isolate', *log, '--mode', 'container',
                              '--root', '/', '--', python, '-B', '-c', DAEMON], cwd='/',
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        err = bytearray()
        err_done = threading.Event()

        def drain():   # (a log fills the pipe otherwise)
            while chunk := os.read(p.stderr.fileno(), 65536):
                err.extend(chunk)
            err_done.set()
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        out_eof, out = eof_after(p.stdout, 5)
        p.wait(timeout=10)
        err_eof = err_done.wait(2)
        alive = daemons()
        for pid in alive:
            os.kill(pid, 9)
        reader.join(5)
        p.stdout.close()
        p.stderr.close()
        ok = out_eof and b'started' in out and alive and (err_eof if not log else not err_eof)
        print('PASS:' if ok else 'FAIL:', 'a daemon with its stdio let go: the caller\'s stdout at EOF'
              + (', stderr kept for the broker\'s log' if log else ', stderr too'), *what,
              '' if ok else [out_eof, out, err_eof, bytes(err[-300:]), alive])
        if not ok:
            failures.append(what)
if failures:
    sys.exit(1)
