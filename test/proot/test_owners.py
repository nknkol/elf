#!/usr/bin/env python3
"""Owner metadata (docs/OCI.md, R5): with --owner-db the guest's chown and
chmod are recorded in a database every process of the view shares, and
stat reports them; the host files keep the app's owner.

Expected: unrecorded files of the user read as root's (also under --user);
chown records uid/gid (lchown the link itself), chmod the full mode while
the host keeps owner rw (rwx for directories) and drops what it refuses;
a file a fake non-root user creates is theirs; a non-root user cannot give
a file away or chmod another's (EPERM); a replacing rename drops the old
object's record; children see the records; tools/oci/owners.py reads them
back by guest path. Both builds, plain and with --isolate."""
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
sys.path.insert(0, str(lib.REPO / 'tools' / 'oci'))
import owners  # noqa: E402

GUEST = r'''
import errno, json, os, subprocess, sys
def owner(p, follow=True):
    st = os.stat(p, follow_symlinks=follow)
    return [st.st_uid, st.st_gid, oct(st.st_mode & 0o7777)]
def attempt(f, *args):
    try:
        f(*args)
        return 0
    except OSError as e:
        return errno.errorcode[e.errno]
out = {}
out['plain'] = owner('/w/plain')[:2]
open('/w/f', 'w').close()
os.chown('/w/f', 1000, 1001)
out['chown'] = owner('/w/f')[:2]
os.chmod('/w/f', 0o4751)
out['chmod'] = owner('/w/f')
os.mkdir('/w/d')
os.chmod('/w/d', 0o500)
out['dir'] = owner('/w/d')
os.symlink('f', '/w/l')
os.chown('/w/l', 7, 8, follow_symlinks=False)
out['lchown'] = [owner('/w/l', False)[:2], owner('/w/f')[:2]]
# The record follows the object: a replacing rename drops the old one.
open('/w/old', 'w').close()
os.chown('/w/old', 5, 5)
open('/w/new', 'w').close()
os.rename('/w/new', '/w/old')
out['rename'] = owner('/w/old')[:2]
out['child'] = subprocess.run([sys.executable, '-B', '-c',
    'import os; st = os.stat("/w/f"); print(st.st_uid, st.st_gid, oct(st.st_mode & 0o7777))'],
    capture_output=True, text=True).stdout.strip()
# A fake non-root user: owns what it creates, cannot give files away.
pid = os.fork()
if pid == 0:
    os.setgid(1001)
    os.setuid(1000)
    r = {}
    open('/w/mine', 'w').close()
    os.mkdir('/w/mydir', 0o700)
    r['mine'] = [owner('/w/mine')[:2], owner('/w/mydir')[:2]]
    r['give'] = attempt(os.chown, '/w/mine', 0, 0)
    r['group'] = attempt(os.chown, '/w/mine', -1, 1001)
    r['others'] = attempt(os.chmod, '/w/plain', 0o600)
    r['own'] = attempt(os.chmod, '/w/mine', 0o600)
    open('/w/child.json', 'w').write(json.dumps(r))
    os._exit(0)
os.waitpid(pid, 0)
out['user'] = json.load(open('/w/child.json'))
os.chown('/w/f', 0, 0)
os.chmod('/w/f', 0o644)
out['reset'] = owner('/w/f')
os.chown('/w/f', 33, 33)
print('RESULT ' + json.dumps(out))
'''

python = Path(sys.executable).resolve()
uid, gid = os.getuid(), os.getgid()
with tempfile.TemporaryDirectory(prefix='owners-', dir=lib.mode_capable()) as tmp:
    for suffix, loader in lib.loaders():
        for isolate in ([], ['--isolate']):
            work = Path(tmp, 'w' + suffix + ''.join(isolate))
            work.mkdir()
            (work / 'plain').write_text('p')
            db = Path(tmp, 'owners' + suffix + ''.join(isolate) + '.db')
            owners.create(db, {})
            common = [str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container', '--root', '/',
                      '-v', f'{work}:/w', '--owner-db', str(db)]
            p = subprocess.run([*common, '--', str(python).lstrip('/'), '-B', '-c', GUEST],
                               cwd='/', capture_output=True, text=True, timeout=180)
            lines = [line for line in p.stdout.splitlines() if line.startswith('RESULT ')]
            what = (loader.name, isolate)
            assert p.returncode == 0 and lines, (what, p.returncode, p.stdout[-2000:], p.stderr[-3000:])
            out = json.loads(lines[-1][7:])
            assert out['plain'] == [0, 0], (what, out)
            assert out['chown'] == [1000, 1001], (what, out)
            assert out['chmod'] == [1000, 1001, '0o4751'], (what, out)
            assert out['dir'] == [0, 0, '0o500'], (what, out)
            assert out['lchown'] == [[7, 8], [1000, 1001]], (what, out)
            assert out['rename'] == [0, 0], (what, out)
            assert out['child'] == '1000 1001 0o4751', (what, out)
            assert out['user'] == {'mine': [[1000, 1001], [1000, 1001]], 'give': 'EPERM', 'group': 0,
                                   'others': 'EPERM', 'own': 0}, (what, out['user'])
            assert out['reset'] == [0, 0, '0o644'], (what, out)
            # The host files keep the app's owner; the host mode keeps owner
            # rw/rwx and lacks what it refused.
            for name in ('f', 'd', 'mine'):
                st = os.lstat(work / name)
                assert (st.st_uid, st.st_gid) == (uid, gid), (what, name, st)
            assert stat.S_IMODE(os.lstat(work / 'd').st_mode) == 0o700, what
            # Read back by guest path (build, commit and diff use this).
            view = owners.guest_view(work, db)
            assert view.get('/f') == (33, 33, None), (what, view.get('/f'))
            assert view.get('/mine', (0, 0, None))[:2] == (1000, 1001), (what, view)
            assert view.get('/d') == (0, 0, 0o500), (what, view.get('/d'))
            assert '/plain' not in view and '/old' not in view, (what, view)
            # The same view with --user: unrecorded files are still root's.
            p = subprocess.run([*common, '--user', '1000:1000', '--', str(python).lstrip('/'), '-B', '-c',
                                'import os; print(os.stat("/w/plain").st_uid, os.stat("/w/f").st_uid)'],
                               cwd='/', capture_output=True, text=True, timeout=60)
            assert p.returncode == 0 and p.stdout.split() == ['0', '33'], (what, p.stdout, p.stderr[-1000:])
            print('PASS: owner database (chown, chmod, creation, rename, users, children):',
                  loader.name, *isolate)
