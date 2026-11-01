#!/usr/bin/env python3
"""Layer images (docs/OCI.md, R6 "层镜像"), host side: tools/oci/erofs.py
writes images that read back as the tree they came from, from a directory
and from a layer tar (whiteouts, hard links, owners, setuid, devices), and
its cache expansion gives the same tree. With erofs-utils installed (dev
host), fsck.erofs accepts the images and images made by mkfs.erofs read
back the same."""
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools/oci'))
import erofs  # noqa: E402

failures = []


def check(cond, what, detail=''):
    print(('PASS: ' if cond else 'FAIL: ') + what)
    if not cond:
        failures.append(what)
        if detail:
            print('   ', str(detail)[:2000])


def fixture(root):
    (root / 'a' / 'b').mkdir(parents=True)
    (root / 'empty').mkdir()
    (root / 'a' / 'f').write_text('hi\n')
    (root / 'a' / 'big').write_bytes(os.urandom(10000))
    (root / 'a' / 'exact').write_bytes(os.urandom(8192))
    (root / 'a' / 'plain').write_bytes(b'x' * 4070)      # tail too long to be inline
    (root / 'a' / 'zero').write_bytes(b'')
    os.symlink('../a/f', root / 'a' / 'b' / 'up')
    os.symlink('/' + 'p' * 4000, root / 'longlink')       # target stored in a block
    os.mkfifo(root / 'fifo')
    for i in range(700):                                   # several directory blocks
        (root / 'a' / 'b' / f'name-{i:04d}-{"s" * 20}').write_text(str(i))
    (root / '.wh.gone').write_text('')
    (root / 'a' / '-sorts-before-dot').write_text('d')
    os.chmod(root / 'a' / 'big', 0o755)


def view(img):
    out = {}
    for path, ino in img.walk():
        kind = stat.S_IFMT(ino.mode)
        data = img.read(ino) if kind in (stat.S_IFREG, stat.S_IFLNK) else b''
        out[path] = (kind, ino.mode & 0o7777, data, ino.uid, ino.gid)
    return out


def tree(root, modes=True):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            rel = '/' + os.path.relpath(p, root)
            if os.path.basename(p).startswith('.wh..elf-'):
                continue
            st = os.lstat(p)
            kind = stat.S_IFMT(st.st_mode)
            data = (os.readlink(p).encode() if kind == stat.S_IFLNK else
                    Path(p).read_bytes() if kind == stat.S_IFREG else b'')
            perm = stat.S_IMODE(st.st_mode) & ~0o6000 if kind != stat.S_IFLNK else 0o777
            if kind == stat.S_IFDIR:
                perm |= 0o700
            out[rel] = (kind, perm if modes else 0, data)
    return out


def main():
    base = os.environ.get('ELF_TEST_TMP')
    if not base and os.path.isdir('/data/storage/el2/base/cache'):
        base = '/data/storage/el2/base/cache'   # HarmonyOS: storage that keeps modes and FIFOs
    work = Path(tempfile.mkdtemp(prefix='erofs-check-', dir=base))
    try:
        src = work / 'src'
        src.mkdir()
        fixture(src)
        image = work / 'dir.erofs'
        erofs.from_dir(src, image, {'owners': {'/a/f': [12, 34]}, 'modes': {'/a/big': 0o4755}},
                       build_time=1700000000)
        with erofs.Image(image) as img:
            got = view(img)
            want = tree(src)
            same = all(got.get(p, (None,))[0] == v[0] and got[p][2] == v[2] for p, v in want.items())
            check(same and set(got) == set(want), 'directory image reads back the same tree',
                  sorted(set(got) ^ set(want))[:10])
            check(got['/a/f'][3:] == (12, 34) and got['/a/big'][1] == 0o4755,
                  'meta.json owners and modes are in the image', (got['/a/f'][3:], oct(got['/a/big'][1])))
        # Layer tar: whiteouts, opaque marker, hard link, device, owner from the header.
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w') as tar:
            def add(name, kind=tarfile.REGTYPE, data=b'', **kw):
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(data) if kind == tarfile.REGTYPE else 0
                info.mode = kw.pop('mode', 0o644)
                for k, v in kw.items():
                    setattr(info, k, v)
                tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
            add('etc', tarfile.DIRTYPE, mode=0o755)
            add('etc/passwd', data=b'root:x:0:0\n', uid=0)
            add('etc/shadow', data=b'secret', mode=0o640, uid=0, gid=42)
            add('etc/.wh.old')
            add('var/.wh..wh..opq')
            add('bin/su', data=b'\x7fELF', mode=0o4755)
            add('bin/su2', tarfile.LNKTYPE, linkname='bin/su')
            add('dev/null', tarfile.CHRTYPE, devmajor=1, devminor=3, mode=0o666)
            add('etc/passwd', data=b'root:x:0:0:new\n')   # a later entry replaces
        blob = work / 'layer.tar'
        blob.write_bytes(raw.getvalue())
        limage = work / 'layer.erofs'
        erofs.from_layer(blob, limage)
        with erofs.Image(limage) as img:
            got = view(img)
            su, su2 = img.lookup('bin/su'), img.lookup('bin/su2')
            dev = img.lookup('dev/null')
            check(got['/etc/passwd'][2] == b'root:x:0:0:new\n' and got['/etc/shadow'][4] == 42 and
                  '/etc/.wh.old' in got and '/var/.wh..wh..opq' in got and su.nid == su2.nid and
                  su.nlink == 2 and su.mode & 0o4000 and stat.S_ISCHR(dev.mode) and dev.u == erofs.encode_dev(1, 3),
                  'layer image: whiteouts, later entries, hard link, setuid, device, owners', sorted(got))
        # Cache expansion (the loader's protocol, here on the host).
        cache = work / 'cache'
        cache.mkdir()
        erofs.ensure(image, cache, 'a/b/up')
        check((cache / 'a' / 'b' / erofs.MARKER).exists() and not (cache / 'empty' / erofs.MARKER).exists(),
              'expansion is per directory, on the way only')
        st = os.lstat(cache / 'a' / 'big')
        check(erofs.placeholder(st) and st.st_size == 10000 and st.st_mode & 0o777 == 0o755,
              'a placeholder has the size, mode and the atime mark', (st.st_size, oct(st.st_mode), st.st_atime))
        ino_before = st.st_ino
        erofs.ensure(image, cache, 'a/big', fill_file=True)
        st = os.lstat(cache / 'a' / 'big')
        check(not erofs.placeholder(st) and st.st_ino == ino_before and
              (cache / 'a' / 'big').read_bytes() == (src / 'a' / 'big').read_bytes(),
              'fill writes the content in place (same inode)')
        erofs.materialize(image, cache)
        a, b = tree(src), tree(cache)
        if '/fifo' not in b:   # storage that refuses FIFOs (HarmonyOS app storage): skipped
            print('NOTE: the cache storage refuses FIFOs; skipped as the protocol allows')
            a.pop('/fifo')
        check(a == b, 'a fully expanded cache equals the source tree', sorted(k for k in set(a) | set(b)
                                                                               if a.get(k) != b.get(k))[:10])
        if shutil.which('fsck.erofs'):
            for im in (image, limage):
                p = subprocess.run(['fsck.erofs', str(im)], capture_output=True, text=True)
                check(p.returncode == 0, f'fsck.erofs accepts {im.name}', p.stdout + p.stderr)
        if shutil.which('mkfs.erofs'):
            made = work / 'mkfs.erofs'
            p = subprocess.run(['mkfs.erofs', str(made), str(src)], capture_output=True, text=True)
            check(p.returncode == 0, 'mkfs.erofs makes an image of the fixture', p.stderr)
            if p.returncode == 0:
                with erofs.Image(made) as img:
                    got = {k: v[:3] for k, v in view(img).items()}
                want = {k: (v[0], v[1] if v[0] != stat.S_IFDIR else v[1], v[2]) for k, v in tree(src).items()}
                check({k: (v[0], v[2]) for k, v in got.items()} == {k: (v[0], v[2]) for k, v in want.items()},
                      'an image made by mkfs.erofs reads back the same tree')
                cache2 = work / 'cache2'
                cache2.mkdir()
                erofs.materialize(made, cache2)
                check(tree(cache2) == tree(src), 'an mkfs.erofs image expands to the same tree')
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if failures:
        print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
        sys.exit(1)
    print('ALL PASS')


if __name__ == '__main__':
    main()
