#!/usr/bin/env python3
"""A directory swapped for a symlink after resolution cannot redirect a
guarded write outside the view.

The guest (host python, root "/" read-only, one writable bind) keeps
creating /rw/dir/victim while another thread keeps swapping /rw/dir for a
symlink to a directory outside the writable mount. Resolution sees the
real directory, the kernel would follow the symlink: the guarded build
walks the parent with O_NOFOLLOW instead, so nothing is ever written
outside."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
loader = lib.loader('-guarded')

GUEST = r'''
import os, sys, threading, time
rw, outside = sys.argv[1], sys.argv[2]
stop = False; written = [0]; refused = [0]
os.mkdir(rw + "/dir")
def swap():
    while not stop:
        os.rename(rw + "/dir", rw + "/real")
        os.symlink(outside, rw + "/link"); os.rename(rw + "/link", rw + "/dir")
        os.unlink(rw + "/dir"); os.rename(rw + "/real", rw + "/dir")
def write():
    while not stop:
        try:
            fd = os.open(rw + "/dir/victim", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, b"x"); os.close(fd); written[0] += 1
        except OSError:
            refused[0] += 1
threads = [threading.Thread(target=swap), threading.Thread(target=write)]
for t in threads: t.start()
time.sleep(6); stop = True
for t in threads: t.join()
print("written", written[0], "refused", refused[0])
# The final name swapped for a symlink to a file outside: a followed call
# (chmod) must never reach that file.
stop = False
open(rw + "/target", "w").close()
def swap_final():
    while not stop:
        os.rename(rw + "/target", rw + "/kept")
        os.symlink(outside + "/file", rw + "/link"); os.rename(rw + "/link", rw + "/target")
        os.unlink(rw + "/target"); os.rename(rw + "/kept", rw + "/target")
def chmod():
    while not stop:
        try: os.chmod(rw + "/target", 0o600)
        except OSError: pass
threads = [threading.Thread(target=swap_final), threading.Thread(target=chmod)]
for t in threads: t.start()
time.sleep(4); stop = True
for t in threads: t.join()
'''

with tempfile.TemporaryDirectory(prefix='path-race-', dir=build) as tmp:
    root = Path(tmp)
    (root / 'rw').mkdir()
    # Storage that honours chmod, so the final-name phase can observe it.
    outside = Path(tempfile.mkdtemp(prefix='path-race-outside-'))
    (outside / 'file').write_text('outside')
    (outside / 'file').chmod(0o644)
    chmod_works = (outside / 'file').stat().st_mode & 0o777 == 0o644
    python = str(Path(sys.executable).resolve())
    p = subprocess.run([str(loader), '--mode', 'container', '--root', '/',
                        '-v', f'{root}/rw:/rw', '--guard-file-mutations', 'rw',
                        '--allow-stdio-output', '--allow-pipe-output', '--',
                        python.lstrip('/'), '-B', '-c', GUEST, '/rw', str(outside)],
                       cwd='/', capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr[-2000:])
    escaped = [f for f in outside.iterdir() if f.name != 'file']
    mode = (outside / 'file').stat().st_mode & 0o777
    shutil.rmtree(outside)
    assert not escaped, (escaped, p.stdout)
    assert not chmod_works or mode == 0o644, oct(mode)
    print('PASS: guarded writes never follow a symlink swapped in after resolution:',
          p.stdout.strip())
