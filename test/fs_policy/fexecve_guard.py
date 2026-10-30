#!/usr/bin/env python3
"""fexecve under the read guard executes only FDs with a readable origin.

fexecve loads the FD's object without a path check, so the FD itself must
carry a known origin the read policy allows: an FD opened by guest path
runs, an FD of unknown origin (relative to the unknown initial cwd) is
refused with EACCES."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']
true = shutil.which('true')
if not true:
    print('SKIP: no true program')
    raise SystemExit(0)

GUEST = r'''
import os, sys
def run(fd):
    pid = os.fork()
    if not pid:
        try:
            os.execve(fd, ["true"], {})
        except OSError as exc:
            os._exit(100 + exc.errno)
    return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
known = os.open("/fexec/true", os.O_RDONLY)
unknown = os.open("fexec/true", os.O_RDONLY)   # Unknown initial cwd.
print("known", run(known), "unknown", run(unknown))
'''

with tempfile.TemporaryDirectory(prefix='fexecve-guard-', dir=build) as tmp:
    shutil.copy2(Path(true).resolve(), Path(tmp) / 'true')
    python = str(Path(sys.executable).resolve())
    p = subprocess.run([str(loader), '--mode', 'container', '--root', '/', '-v', f'{tmp}:/fexec',
                        '--guard-file-access', 'rr', '--allow-stdio-output',
                        '--allow-pipe-output', '--',
                        python.lstrip('/'), '-B', '-c', GUEST],
                       cwd='/', capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr[-1500:])
    assert p.stdout.split() == ['known', '0', 'unknown', '113'], p.stdout  # 100 + EACCES
    print('PASS: guarded fexecve needs a readable FD origin')
