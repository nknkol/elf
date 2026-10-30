#!/usr/bin/env python3
"""PRoot fake_id0: tracked guest credentials, chown and owner reporting.

apt-style privilege dropping must be observable (getresuid follows
setresuid, root cannot be regained), a fake root may chown away from
itself, and credentials survive exec. Both builds."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'

GUEST = r'''
import json, os, subprocess, sys
work = sys.argv[1]
out = {"start": [os.getresuid(), os.getresgid()]}
path = work + "/owned"
open(path, "w").close()
out["own"] = [os.stat(path).st_uid, os.stat(path).st_gid]
os.chown(path, 4321, 4321)                       # EPERM for the real user: faked.
out["give"] = "ok"
try:
    os.chown(work + "/missing", 1, 1)
except FileNotFoundError:
    out["missing"] = "ENOENT"
out["groups0"] = os.getgroups()
os.setgroups([5, 6])
out["groups"] = os.getgroups()
out["uname"] = [os.uname().sysname, os.uname().release]
out["exec_groups"] = subprocess.run([sys.executable, "-B", "-c",
                                     "import os; print(os.getgroups(), os.uname().release)"],
                                    capture_output=True, text=True).stdout.strip()
os.setgroups([])
os.setresgid(105, 105, 105)
os.setresuid(105, 105, 105)                      # apt's DropPrivileges.
out["dropped"] = [os.getresuid(), os.getresgid(), os.getuid(), os.geteuid()]
out["own_after"] = os.stat(path).st_uid          # Owner follows the saved id.
for name, call in (("setuid0", lambda: os.setuid(0)), ("seteuid0", lambda: os.seteuid(0)),
                   ("groups_dropped", lambda: os.setgroups([]))):
    try:
        call(); out[name] = "allowed"
    except PermissionError:
        out[name] = "EPERM"
child = subprocess.run([sys.executable, "-B", "-c",
                        "import os; print(os.getresuid(), os.getresgid())"],
                       capture_output=True, text=True)
out["exec"] = child.stdout.strip()
print("RESULT " + json.dumps(out))
'''

python = str(Path(sys.executable).resolve())
with tempfile.TemporaryDirectory(prefix='fake-ids-', dir=build) as tmp:
    for suffix in ('', '-fd-experiment'):
        loader = build / f'elfloader-proot{suffix}'
        manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
        assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
        # The bind's host owner counts as the caller's (service-owned storage).
        p = subprocess.run([str(loader), '--mode', 'container', '--root', '/', '-v', f'{tmp}:/fake-ids',
                            '--kernel-release', '6.1.0-elf', '--kernel-sysname', 'Linux',
                            '--', python.lstrip('/'), '-B', '-c', GUEST, '/fake-ids'],
                           cwd='/', capture_output=True, text=True, timeout=120)
        lines = [line for line in p.stdout.splitlines() if line.startswith('RESULT ')]
        assert p.returncode == 0 and lines, (suffix, p.returncode, p.stdout, p.stderr[-2000:])
        out = json.loads(lines[-1][7:])
        expected = {'start': [[0, 0, 0], [0, 0, 0]], 'own': [0, 0], 'give': 'ok',
                    'missing': 'ENOENT',
                    'dropped': [[105, 105, 105], [105, 105, 105], 105, 105], 'own_after': 105,
                    'setuid0': 'EPERM', 'seteuid0': 'EPERM', 'groups': [5, 6],
                    'groups0': [0], 'uname': ['Linux', '6.1.0-elf'],
                    'exec_groups': '[5, 6] 6.1.0-elf', 'groups_dropped': 'EPERM',
                    'exec': '(105, 105, 105) (105, 105, 105)'}
        assert out == expected, (suffix, out)
        Path(tmp, 'owned').unlink()
        print('PASS: fake root credentials, privilege drop, chown and exec:', loader.name)
