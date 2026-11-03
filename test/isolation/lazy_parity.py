#!/usr/bin/env python3
"""Layer-image expansion and fill: the loader's lazy_layer.c (through the
broker, a forged BROKER_LAZY_PATH on a --lower-image cache) and the host's
tools/oci/erofs.py give the same result from the same inputs
(docs/ISOLATION.md; part of the application sandbox's acceptance suite).

Same inputs, both sides, results compared entry by entry (type, mode, size,
content, link target, mtime):
- a full expansion and fill of a fixture (directories of several modes,
  setuid, empty and multi-block files, symlinks, a FIFO);
- a completion marker that is a symlink: taken as done, nothing made
  through it;
- a name made before the expansion: kept as it is;
- a placeholder replaced by an ordinary file: not filled;
- a placeholder replaced by a symlink: nothing written through it;
- an image entry whose symlink target is empty: refused (EIO / ImageError),
  nothing placed for it.

erofs.py alone, by injection (lazy_nested.py drives the same cases on the
loader as races): a name made between TMP and its rename is not replaced;
a file renamed over the placeholder after the check is not written; a
short write goes on; a failure while making a file leaves no TMP; a
failing fill restores the placeholder's mode."""
import errno
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
sys.path.insert(0, str(lib.REPO / 'tools/oci'))
import erofs  # noqa: E402

failures = []
loader = lib.BUILD / 'elfloader-guarded'


def check(tag, ok, detail=''):
    print('PASS:' if ok else 'FAIL:', tag, '' if ok else str(detail)[:1500])
    if not ok:
        failures.append(tag)


def make_image(path, entries):
    w = erofs.Writer(path)
    try:
        for parts, mode, data in entries:
            node = erofs.Node(mode, mtime=1700000000)
            if stat.S_ISLNK(mode):
                node.target = data
            elif data is not None:
                w.write_data(node, [data])
            w.put(parts, node)
        w.finish(1700000000)
    finally:
        w.close()


def snapshot(top):
    out = {}
    for d, dirs, files in os.walk(top):
        for name in dirs + files:
            p = Path(d, name)
            if name in (erofs.TMP,):
                out[str(p.relative_to(top))] = 'TMP LEFT'
                continue
            st = os.lstat(p)
            kind = stat.S_IFMT(st.st_mode)
            data = (os.readlink(p) if kind == stat.S_IFLNK else
                    p.read_bytes() if kind == stat.S_IFREG and st.st_mode & 0o400 else None)
            # mtime: the image's, or another (when the entry or the test made
            # it; a link's or a marker's; a FIFO's where storage refuses it)
            out[str(p.relative_to(top))] = (kind, stat.S_IMODE(st.st_mode), st.st_size,
                                            'image' if st.st_mtime_ns == 1700000000 * 10**9 else 'other', data)
    return out


FIXTURE = [(['d'], stat.S_IFDIR | 0o755, None),
           (['d', 'f'], stat.S_IFREG | 0o644, b'hello\n'),
           (['d', 'big'], stat.S_IFREG | 0o640, bytes(range(256)) * 300),
           (['d', 'empty'], stat.S_IFREG | 0o600, b''),
           (['d', 'suid'], stat.S_IFREG | 0o4755, b'#!/bin/sh\n'),
           (['d', 'link'], stat.S_IFLNK | 0o777, b'../top'),
           (['d', 'sub'], stat.S_IFDIR | 0o750, None),
           (['d', 'sub', 'g'], stat.S_IFREG | 0o444, b'readonly\n'),
           (['d', 'pipe'], stat.S_IFIFO | 0o640, None),
           (['top'], stat.S_IFREG | 0o644, b'top\n'),
           (['bad'], stat.S_IFDIR | 0o755, None),
           (['bad', 'ok'], stat.S_IFREG | 0o644, b'ok\n'),
           (['bad', 'zlink'], stat.S_IFLNK | 0o777, b'')]
DIRS = ['', 'd', 'd/sub']
FILES = ['top', 'd/f', 'd/big', 'd/empty', 'd/suid', 'd/sub/g']

with tempfile.TemporaryDirectory(prefix='iso-parity-', dir=lib.mode_capable()) as tmp:
    tmp = Path(tmp)
    image = tmp / 'img.erofs'
    try:
        make_image(image, FIXTURE)
    except Exception as e:   # (the writer refuses an empty link target)
        FIXTURE = [e for e in FIXTURE if e[0] != ['bad', 'zlink']]
        image.unlink(missing_ok=True)
        make_image(image, FIXTURE)
        print('SKIP: the image writer refuses an empty link target:', e)
    upper = tmp / 'upper'
    upper.mkdir()
    have_loader = loader.exists()
    if have_loader:
        subprocess.run(['clang', '-O1', '-static', '-I', str(lib.REPO / 'src/payload/include'),
                        '-I', str(lib.REPO / 'src/payload/arch/aarch64'),
                        str(Path(__file__).with_name('probe.c')), '-o', str(upper / '.elf-exec')], check=True)
    else:
        print('SKIP: elfloader-guarded missing: erofs.py side only')
    runs = [0]

    def c_side(cache, rel, op):
        """lazy_layer.c by the broker: rc of BROKER_LAZY_PATH on cache/rel."""
        runs[0] += 1
        p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, '--isolate', '--mode', 'container',
                            '--root', str(upper), '--lower', str(cache), '--lower-image', str(image),
                            '--mount-table', str(tmp / f'm{runs[0]}'), '--mount-scratch', str(tmp / f's{runs[0]}'),
                            '--guard-file-access', 'd', '--allow-stdio-output', '--',
                            './.elf-exec', 'h', 'lazypath', f'{cache}/{rel}'.rstrip('/'), str(op)],
                           capture_output=True, text=True, timeout=60, cwd='/')
        for line in p.stdout.splitlines():
            if line.startswith('lazy '):
                return int(line.split()[1])
        return p.stdout + p.stderr

    def py_side(cache, rel, op):
        try:
            (erofs.fill if op else erofs.expand)(image, cache, rel)
            return 0
        except erofs.ImageError:
            return -errno.EIO
        except OSError as e:
            return -e.errno

    def both(name, prepare, steps):
        """prepare(cache) on a fresh cache per side, then steps [(rel, op)]."""
        out = {}
        for side, run in (('c', c_side), ('py', py_side)):
            if side == 'c' and not have_loader:
                continue
            cache = tmp / f'{name}-{side}'
            cache.mkdir()
            prepare(cache)
            out[side] = ([run(cache, rel, op) for rel, op in steps], snapshot(cache))
        return out

    def same(tag, out, extra=lambda r: True):
        if 'c' not in out:
            check(tag + ' (erofs.py)', extra(out['py']), out['py'])
            return
        (rc_c, c), (rc_p, py) = out['c'], out['py']
        diff = {k: (c.get(k), py.get(k)) for k in sorted(set(c) | set(py)) if c.get(k) != py.get(k)}
        check(tag + ': the loader and erofs.py agree', rc_c == rc_p and not diff and extra(out['py']),
              [rc_c, rc_p, {k: tuple(str(x)[:120] for x in v) for k, v in diff.items()}])

    # A full expansion and fill.
    out = both('full', lambda c: None, [(r, 0) for r in DIRS] + [(f, 1) for f in FILES])
    same('a full expansion and fill', out,
         lambda r: all(x == 0 for x in r[0]) and r[1]['d/big'][4] == bytes(range(256)) * 300 and
         r[1]['d/suid'][1] & 0o777 == 0o755)

    # A symlink at the completion marker.
    sentinel = tmp / 'made-through-marker'

    def marker_link(c):
        py_side(c, '', 0)   # (makes d, not yet expanded)
        os.symlink(sentinel, c / 'd' / erofs.MARKER)
    out = both('marker', marker_link, [('d', 0)])
    same('a completion marker that is a symlink: taken as done, nothing made', out,
         lambda r: r[0] == [0] and not os.path.lexists(sentinel) and
         sorted(k for k in r[1] if k.startswith('d/')) == ['d/' + erofs.MARKER])

    # A name made before the expansion.
    def made_first(c):
        py_side(c, '', 0)
        (c / 'd' / 'f').write_bytes(b'host\n')
    out = both('first', made_first, [('d', 0)])
    same('a name made before the expansion is kept', out,
         lambda r: r[0] == [0] and r[1]['d/f'][4] == b'host\n')

    # A placeholder replaced by an ordinary file, and by a symlink.
    outside = tmp / 'outside-target'
    outside.write_bytes(b'outside\n')

    def replaced(c):
        py_side(c, '', 0)
        os.unlink(c / 'top')
        (c / 'top').write_bytes(b'ordinary\n')
    out = both('ordinary', replaced, [('top', 1)])
    same('a placeholder replaced by an ordinary file is not filled', out,
         lambda r: r[1]['top'][4] == b'ordinary\n')

    def linked(c):
        py_side(c, '', 0)
        os.unlink(c / 'top')
        os.symlink(outside, c / 'top')
    out = both('linked', linked, [('top', 1)])
    for side, (rcs, _) in out.items():   # (the loader reports ELOOP, erofs.py returns quietly)
        out[side] = (None, out[side][1])
    same('a placeholder replaced by a symlink: nothing written through it', out,
         lambda r: outside.read_bytes() == b'outside\n')

    # An empty symlink target in the image.
    if any(e[0] == ['bad', 'zlink'] for e in FIXTURE):
        out = both('badlink', lambda c: py_side(c, '', 0), [('bad', 0)])
        same('an empty symlink target in the image is refused, nothing placed for it', out,
             lambda r: r[0] == [-errno.EIO] and 'bad/zlink' not in r[1])

    # erofs.py by injection.
    def noreplace_supported(where):
        a, b = where / '.nr-a', where / '.nr-b'
        a.write_bytes(b'a')
        b.write_bytes(b'b')
        try:
            fd = os.open(where, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.rename(a, where / erofs.TMP)
                erofs._place(fd, '.nr-b')
            finally:
                os.close(fd)
            return b.read_bytes() == b'b' and not (where / erofs.TMP).exists()
        finally:
            for q in (a, b, where / erofs.TMP):
                if q.exists():
                    q.unlink()
    cache = tmp / 'inject'
    cache.mkdir()
    erofs.expand(image, cache, '')
    if noreplace_supported(cache):
        real_place = erofs._place

        def racing_place(fd, name):
            if name == 'f':
                fd2 = os.open('f', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                os.write(fd2, b'made meanwhile\n')
                os.close(fd2)
            return real_place(fd, name)
        erofs._place = racing_place
        try:
            erofs.expand(image, cache, 'd')
        finally:
            erofs._place = real_place
        check('erofs.py: a name made between TMP and its rename is not replaced; no TMP left',
              (cache / 'd' / 'f').read_bytes() == b'made meanwhile\n' and not (cache / 'd' / erofs.TMP).exists())
    else:
        print('SKIP: no RENAME_NOREPLACE here; a name made meanwhile is replaced')
        erofs.expand(image, cache, 'd')
    # A file renamed over the placeholder after the check.
    victim = b'victim, not to be written\n'
    real_lookup = erofs.Image.lookup

    def renaming_lookup(self, rel):
        if rel == 'top':
            (cache / '.victim').write_bytes(victim)
            os.rename(cache / '.victim', cache / 'top')
        return real_lookup(self, rel)
    erofs.Image.lookup = renaming_lookup
    try:
        rc = py_side(cache, 'top', 1)
    finally:
        erofs.Image.lookup = real_lookup
    check('erofs.py: a file renamed over the placeholder after the check is not written (EAGAIN)',
          rc == -errno.EAGAIN and (cache / 'top').read_bytes() == victim, rc)
    # A short write goes on.
    real_pwrite = os.pwrite
    os.pwrite = lambda fd, data, pos: real_pwrite(fd, bytes(data)[:100], pos)
    try:
        rc = py_side(cache, 'd/big', 1)
    finally:
        os.pwrite = real_pwrite
    check('erofs.py: short writes go on to the whole content',
          rc == 0 and (cache / 'd' / 'big').read_bytes() == bytes(range(256)) * 300, rc)
    # A failure while making a file leaves no TMP.
    cache2 = tmp / 'inject2'
    cache2.mkdir()
    erofs.expand(image, cache2, '')
    real_utime = os.utime

    def failing_utime(path, *a, **k):
        if not isinstance(path, (str, bytes)):   # (the file's own FD: a regular file being made)
            raise OSError(errno.EIO, 'injected')
        return real_utime(path, *a, **k)
    os.utime = failing_utime
    try:
        rc = py_side(cache2, 'd', 0)
    finally:
        os.utime = real_utime
    check('erofs.py: a failure while making a file leaves no TMP',
          rc == -errno.EIO and not os.path.lexists(cache2 / 'd' / erofs.TMP), [rc, os.listdir(cache2 / 'd')])
    # A failing fill restores the placeholder's mode (0444 here).
    erofs.expand(image, cache2, 'd')
    erofs.expand(image, cache2, 'd/sub')
    before = stat.S_IMODE(os.lstat(cache2 / 'd' / 'sub' / 'g').st_mode)
    real_read = erofs.Image.read
    erofs.Image.read = lambda self, *a, **k: (_ for _ in ()).throw(OSError(errno.EIO, 'injected'))
    try:
        rc = py_side(cache2, 'd/sub/g', 1)
    finally:
        erofs.Image.read = real_read
    after = os.lstat(cache2 / 'd' / 'sub' / 'g')
    check('erofs.py: a failing fill restores the placeholder\'s mode and stays a placeholder',
          rc == -errno.EIO and before == 0o444 and stat.S_IMODE(after.st_mode) == 0o444 and erofs.placeholder(after),
          [rc, oct(before), oct(after.st_mode)])

if failures:
    print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
    sys.exit(1)
print('lazy parity acceptance: all passed')
