#!/usr/bin/env python3
"""Copy-on-write root (docs/OCI.md, R6): --root UPPER --lower LOWER shows
the merged view; changes go to UPPER, LOWER is never written.

Expected (Alpine as the lower, BusyBox commands): lower files read and run;
writing, appending, truncating and chmod copy a file up; creating in a
lower directory makes the parents in the upper; rm leaves an OCI whiteout
(.wh.<name>), recreating removes it; a directory removed and made again is
opaque; mv of a lower file works, of a lower directory falls back to
copying (EXDEV); mount -t overlay inside merges its own layers; listings merge the layers and never show whiteouts; rmdir
of a non-empty merged directory fails; a cwd inside a lower directory
reads as its guest path and relative creation lands in the upper; a later
run sees the same view. The lower tree is byte-for-byte unchanged. Both
builds, plain and with --isolate."""
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

LOWER = lib.require(lib.ALPINE)


def digest(root):
    """Names, types, modes, sizes, mtimes and contents of a tree."""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            h.update(f'{os.path.relpath(path, root)} {st.st_mode} {st.st_size} {st.st_mtime_ns}\n'.encode())
            if stat.S_ISREG(st.st_mode):
                with open(path, 'rb') as f:
                    h.update(hashlib.sha256(f.read()).digest())
            elif stat.S_ISLNK(st.st_mode):
                h.update(os.readlink(path).encode())
    return h.hexdigest()


before = digest(LOWER)
release = (LOWER / 'etc/alpine-release').read_text().strip()
keys = sorted(os.listdir(LOWER / 'etc/apk/keys'))
etc_lower = sorted(os.listdir(LOWER / 'etc'))
STEPS = [
    ('read', 'cat /etc/alpine-release', release + '\n'),
    ('write copies up', 'echo new > /etc/motd; echo more >> /etc/motd; cat /etc/motd', 'new\nmore\n'),
    ('truncate', 'printf abc > /etc/group; : > /etc/group; wc -c < /etc/group', '0\n'),
    ('chmod', 'chmod 600 /etc/fstab; stat -c %a /etc/fstab', '600\n'),
    ('create in lower dir', 'mkdir -p /usr/local/new/deep; echo x > /usr/local/new/deep/f; cat /usr/local/new/deep/f',
     'x\n'),
    ('rm leaves whiteout', 'rm /etc/issue; test -e /etc/issue || echo gone; ls -A /etc | grep -c "^issue$"; true',
     'gone\n0\n'),
    ('recreate', 'echo again > /etc/issue; cat /etc/issue', 'again\n'),
    ('remove dir, make it again: opaque', 'rm -r /etc/apk/protected_paths.d; test -d /etc/apk/protected_paths.d || '
     'echo gone; mkdir /etc/apk/protected_paths.d; ls -A /etc/apk/protected_paths.d | wc -l', 'gone\n0\n'),
    ('mv lower file', 'mv /etc/hostname /etc/hostname2; test -e /etc/hostname || cat /etc/hostname2 | wc -l', '1\n'),
    ('mv lower dir (EXDEV, copied)', 'mv /etc/apk/keys /etc/keys2; test -e /etc/apk/keys || ls /etc/keys2',
     ''.join(k + '\n' for k in keys)),
    ('whiteouts never listed', 'find / -xdev -name ".wh.*" | wc -l', '0\n'),
    ('rmdir of a non-empty merged dir', 'rmdir /etc 2>/dev/null || echo refused', 'refused\n'),
    ('cwd in a lower dir', 'cd /usr/bin && pwd && echo here > made && cat /usr/bin/made && /bin/sh -c pwd',
     '/usr/bin\nhere\n/usr/bin\n'),
    ('script in the upper runs', 'printf "#!/bin/sh\\necho ran\\n" > /tmp/s; chmod +x /tmp/s; /tmp/s', 'ran\n'),
    ('mount -t overlay', 'mkdir -p /o/l1 /o/l2 /o/u /o/w /o/m; echo a > /o/l1/a; echo b1 > /o/l1/b; '
     'echo b2 > /o/l2/b; echo c > /o/l2/c; mount -t overlay overlay '
     '-o lowerdir=/o/l1:/o/l2,upperdir=/o/u,workdir=/o/w /o/m && cat /o/m/a /o/m/b /o/m/c && '
     'echo new > /o/m/c && rm /o/m/a && ls /o/m && cat /o/l2/c /o/u/c && grep -c " /o/m overlay" /proc/mounts && '
     'umount /o/m && ls /o/m | wc -l', 'a\nb1\nc\nb\nc\nc\nnew\n1\n0\n'),
    ('exec of a copied-up program', 'mkdir -p /usr/local/bin; cp /bin/busybox /usr/local/bin/busybox; /usr/local/bin/busybox echo ok', 'ok\n'),
]
# What /etc lists at the end.
etc_final = sorted((set(etc_lower) - {'hostname'}) | {'hostname2', 'keys2', 'motd', 'issue'})

with tempfile.TemporaryDirectory(prefix='union-', dir=lib.mode_capable()) as tmp:
    for suffix, loader in lib.loaders():
        for isolate in ([], ['--isolate']):
            what = (loader.name, isolate)
            upper = Path(tmp, 'upper' + suffix + ''.join(isolate))
            upper.mkdir()

            def run(command, timeout=60):
                return subprocess.run([str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container',
                                       '--root', str(upper), '--lower', str(LOWER), '-v', '/dev/null:/dev/null',
                                       '--mount-table', str(upper) + '.mounts', '--mount-scratch',
                                       str(upper) + '.scratch',
                                       '--', 'bin/busybox', 'sh', '-c',
                                       'PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; ' + command],
                                      cwd='/', capture_output=True, text=True, timeout=timeout)
            for name, command, expected in STEPS:
                p = run(command)
                assert p.returncode == 0 and p.stdout == expected, (what, name, p.returncode, p.stdout,
                                                                    p.stderr[-2000:])
            # A later run: the same view; /etc merges both layers.
            p = run('cat /etc/motd /etc/issue; ls -A /etc')
            assert p.returncode == 0, (what, p.stderr[-2000:])
            assert p.stdout.split('\n')[:3] == ['new', 'more', 'again'], (what, p.stdout)
            assert sorted(p.stdout.split()[3:]) == etc_final, (what, sorted(p.stdout.split()[3:]), etc_final)
            # The upper is the layer diff: copies, new files, whiteouts.
            assert (upper / 'etc/motd').read_text() == 'new\nmore\n', what
            assert (upper / 'etc/.wh.hostname').exists() and (upper / 'etc/apk/.wh.keys').exists(), what
            assert not (upper / 'etc/.wh.issue').exists(), what
            assert (upper / 'etc/apk/protected_paths.d/.wh..wh..opq').exists(), what
            assert (upper / 'usr/local/new/deep/f').read_text() == 'x\n', what
            assert stat.S_IMODE((upper / 'etc/fstab').stat().st_mode) & 0o077 == 0, what
            assert not (upper / 'etc/alpine-release').exists(), what
            assert digest(LOWER) == before, (what, 'the lower changed')
            print('PASS: copy-on-write root (copy-up, whiteouts, opaque, EXDEV, listings, cwd):',
                  loader.name, *isolate)
