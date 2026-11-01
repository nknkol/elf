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
builds, plain and with --isolate, with the lower as a directory and as a
layer image (erofs, expanded on demand into a cache: what is read is
filled, the rest stays placeholders; the image file is unchanged; stat
of a placeholder shows the times and blocks of a filled file and leaves it
unfilled; a file opened by openat2 RESOLVE_BENEATH is filled; a FIFO of the
image is in the cache)."""
import hashlib
import os
import shutil
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
    ('exec of a lower program not run before (its libraries too)', '/sbin/apk --version | cut -c1-9',
     'apk-tools\n'),
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

sys.path.insert(0, str(lib.REPO / 'tools/oci'))
import erofs  # noqa: E402

with tempfile.TemporaryDirectory(prefix='union-', dir=lib.mode_capable()) as tmp:
    # R6 layer images: the same steps with the lower as an erofs image,
    # expanded on demand into a cache (a fresh one per run: the payload
    # expands it, or with --isolate the broker).
    image = Path(tmp, 'alpine.erofs')
    w = erofs.Writer(image)
    try:
        w.add_dir(LOWER)
        w.put(['srv', 'pipe'], erofs.Node(stat.S_IFIFO | 0o640))
        w.finish()
    finally:
        w.close()
    probe = lib.build_probe(Path(__file__).with_name('beneath_probe.c'), Path(tmp, 'probe'))
    image_digest = hashlib.sha256(image.read_bytes()).hexdigest()
    runs = [(s, l, i, k) for s, l in lib.loaders() for i in ([], ['--isolate']) for k in ('dir', 'image')]
    for suffix, loader, isolate, kind in runs:
        what = (loader.name, isolate, kind)
        upper = Path(tmp, 'upper' + suffix + ''.join(isolate) + kind)
        upper.mkdir()
        lower = ['--lower', str(LOWER)]
        if kind == 'image':
            cache = Path(tmp, 'cache' + suffix + ''.join(isolate))
            cache.mkdir()
            lower = ['--lower', str(cache), '--lower-image', str(image)]

        def run(command, timeout=60):
            return subprocess.run([str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container',
                                   '--root', str(upper), *lower, '-v', '/dev/null:/dev/null',
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
        if kind == 'image':
            assert hashlib.sha256(image.read_bytes()).hexdigest() == image_digest, (what, 'image changed')
            held = [os.path.join(d, f) for d, _, fs in os.walk(cache) for f in fs
                    if erofs.placeholder(os.lstat(os.path.join(d, f)))]
            assert held and not erofs.placeholder(os.lstat(cache / 'bin/busybox')), \
                (what, 'files read are filled, the others stay placeholders', len(held))
            assert (cache / 'bin/busybox').read_bytes() == (LOWER / 'bin/busybox').read_bytes(), what
            # Placeholders the steps left: stat hides the mark, openat2 fills.
            rels = sorted('/' + os.path.relpath(h, cache) for h in held
                          if not (upper / os.path.relpath(h, cache)).exists())
            def visible(rel):
                parts = rel.strip('/').split('/')
                for i in range(len(parts)):
                    d = upper.joinpath(*parts[:i])
                    if (d / ('.wh.' + parts[i])).exists() or (d / '.wh..wh..opq').exists():
                        return False
                return not rel.startswith('/dev/') and all(c.isalnum() or c in '/._-' for c in rel)
            rels = [r for r in rels if visible(r)]
            first, second = rels[0], rels[-1]
            p = run(f'stat -c "%X %Y %b" {first}')
            fields = p.stdout.split()
            assert p.returncode == 0 and len(fields) == 3 and fields[0] == fields[1] and int(fields[2]) > 0, \
                (what, 'stat of a placeholder', first, p.stdout, p.stderr[-2000:])
            assert erofs.placeholder(os.lstat(cache / first.lstrip('/'))), (what, 'stat fills nothing', first)
            shutil.copy2(probe, upper / 'probe')
            parent, name = second.rsplit('/', 1)
            p = run(f'/probe {parent or "/"} {name}')
            # (The plain build on HarmonyOS reports openat2 as not
            # implemented; the guarded build emulates RESOLVE_BENEATH.)
            unsupported = p.stdout == 'beneath=-38\n' and suffix == '' and os.path.isdir('/data/storage/el2')
            assert p.returncode == 0 and (p.stdout == 'beneath=0\n' or unsupported), \
                (what, 'openat2 beneath', second, p.stdout, p.stderr[-2000:])
            if not unsupported:
                assert not erofs.placeholder(os.lstat(cache / second.lstrip('/'))) and \
                    (cache / second.lstrip('/')).read_bytes() == (LOWER / second.lstrip('/')).read_bytes(), \
                    (what, 'openat2 beneath fills', second)
            os.unlink(upper / 'probe')
            p = run('stat -c "%F %a" /srv/pipe')
            assert p.stdout == 'fifo 640\n' and stat.S_ISFIFO(os.lstat(cache / 'srv/pipe').st_mode), \
                (what, 'a FIFO of the image', p.stdout, p.stderr[-2000:])
        print('PASS: copy-on-write root (copy-up, whiteouts, opaque, EXDEV, listings, cwd):',
              loader.name, *isolate, kind)
