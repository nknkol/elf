#!/usr/bin/env python3
"""Layer-image expansion by the broker never crosses a protected subtree
inside a writable cache (docs/ISOLATION.md; part of the application
sandbox's acceptance suite).

/rw is a writable volume; /rw/cache/protected is also mounted on its own,
read-only (or denied). A forged BROKER_LAZY_MOUNT names an erofs image and
/rw/cache as the cache, and expands or fills names inside protected.

Expected, guarded build with --isolate: every such request is refused
(EACCES) and protected's names, contents and metadata stay as they were;
a cache with nothing protected inside it (/rw/cache2) still expands.

Moved after the check: a writable directory holding a protected subtree
(/rw/outside/holder, holder/protected mounted on its own) is moved into a
cache (/rw/cache3) and out again, over and over, while forged requests
expand and fill names inside holder/protected. Expected: no request
succeeds (refused where the walk meets the protected tree, or the path is
not there) and protected stays as it was."""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
sys.path.insert(0, str(lib.REPO / 'tools/oci'))
import erofs  # noqa: E402

EACCES = -13
failures = []
loader = lib.BUILD / 'elfloader-guarded'
if not loader.exists():
    print('SKIP: elfloader-guarded missing')
    sys.exit(0)


def check(tag, ok, detail=''):
    print('PASS:' if ok else 'FAIL:', tag, '' if ok else detail)
    if not ok:
        failures.append(tag)


def snapshot(top):
    out = {}
    for d, dirs, files in os.walk(top):
        for name in dirs + files:
            p = Path(d, name)
            st = os.lstat(p)
            out[str(p.relative_to(top))] = (st.st_mode, st.st_size, st.st_mtime_ns, st.st_atime_ns,
                                            p.read_bytes() if stat.S_ISREG(st.st_mode) else None)
    return out


with tempfile.TemporaryDirectory(prefix='iso-lazy-', dir=lib.mode_capable()) as tmp:
    tmp = Path(tmp)
    root = tmp / 'root'
    (root / 'rw').mkdir(parents=True)
    (root / 'prot').mkdir()
    probe = root / '.elf-exec'
    subprocess.run(['clang', '-O1', '-static', '-I', str(lib.REPO / 'src/payload/include'),
                    '-I', str(lib.REPO / 'src/payload/arch/aarch64'),
                    str(Path(__file__).with_name('probe.c')), '-o', str(probe)], check=True)
    (tmp / 'rw').mkdir()
    image = tmp / 'rw' / 'img.erofs'   # readable to the guest: only the cache is in question
    w = erofs.Writer(image)
    try:
        for parts, mode, data in ((['top'], stat.S_IFREG | 0o644, b'top\n'),
                                  (['protected'], stat.S_IFDIR | 0o755, None),
                                  (['protected', 'a'], stat.S_IFREG | 0o644, b'aaaa\n'),
                                  (['protected', 'new'], stat.S_IFREG | 0o644, b'new\n')):
            node = erofs.Node(mode, mtime=1700000000)
            if data is not None:
                w.write_data(node, [data])
            w.put(parts, node)
        w.finish(1700000000)
    finally:
        w.close()
    rw = tmp / 'rw'
    cache, cache2 = rw / 'cache', rw / 'cache2'
    for c in (cache, cache2):
        c.mkdir()
    # protected: expanded once on the host (placeholders), then a mount of its own.
    erofs.expand(image, cache, '')
    (cache / 'protected').mkdir(exist_ok=True)
    erofs.expand(image, cache, 'protected')
    os.unlink(cache / 'protected' / 'new')   # a name an expansion would add back
    for vector in ('dwr', 'dwd'):
        before = snapshot(cache / 'protected')

        def forge(cache_dir, rel, op):
            p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, '--isolate', '--mode', 'container',
                                '--root', str(root), '-v', f'{rw}:/rw', '-v', f'{cache}/protected:/prot',
                                '--guard-file-access', vector, '--allow-stdio-output', '--',
                                './.elf-exec', 'h', 'lazy', str(image), str(cache_dir), rel, str(op)],
                               capture_output=True, text=True, timeout=60, cwd='/')
            for line in p.stdout.splitlines():
                if line.startswith('lazy '):
                    return int(line.split()[1]), p.stdout + p.stderr
            return None, p.stdout + p.stderr
        for rel, op, what in (('/protected', 0, 'expand protected'), ('/', 0, 'expand the cache root'),
                              ('/protected/a', 1, 'fill protected/a')):
            rc, out = forge(cache, rel, op)
            check(f'{vector}: {what} inside a protected subtree is refused', rc == EACCES, out)
        check(f'{vector}: protected unchanged (names, contents, metadata)',
              snapshot(cache / 'protected') == before, sorted(snapshot(cache / 'protected')))
    rc, out = forge(cache2, '/', 0)
    check('a cache with nothing protected inside still expands',
          rc == 0 and (cache2 / 'top').exists() and (cache2 / 'protected').is_dir(), out)

    # Moved into the cache after the check.
    image2 = tmp / 'rw' / 'img2.erofs'
    w = erofs.Writer(image2)
    try:
        for parts, mode, data in ((['holder'], stat.S_IFDIR | 0o755, None),
                                  (['holder', 'protected'], stat.S_IFDIR | 0o755, None),
                                  (['holder', 'protected', 'a'], stat.S_IFREG | 0o644, b'aaaa\n'),
                                  (['holder', 'protected', 'new'], stat.S_IFREG | 0o644, b'new\n')):
            node = erofs.Node(mode, mtime=1700000000)
            if data is not None:
                w.write_data(node, [data])
            w.put(parts, node)
        w.finish(1700000000)
    finally:
        w.close()
    cache3, outside = rw / 'cache3', rw / 'outside'
    cache3.mkdir()
    outside.mkdir()
    for rel in ('', 'holder', 'holder/protected'):
        erofs.expand(image2, cache3, rel)
    os.unlink(cache3 / 'holder' / 'protected' / 'new')
    os.unlink(cache3 / 'holder' / 'protected' / '.wh..elf-lazy')
    os.rename(cache3 / 'holder', outside / 'holder')
    protected = outside / 'holder' / 'protected'
    for vector in ('dwr', 'dwd'):
        before = snapshot(protected)
        stop = threading.Event()

        def mover():
            while not stop.is_set():
                os.rename(outside / 'holder', cache3 / 'holder')
                time.sleep(0.0005)
                os.rename(cache3 / 'holder', outside / 'holder')
                time.sleep(0.0005)
        results = {}
        for rel, op in (('/holder/protected', 0), ('/holder/protected/a', 1)):
            # The broker starts with holder outside (its trees are opened
            # then); the moving starts once the guest is ready.
            p = subprocess.Popen([str(loader), *lib.ISOLATE_EXTRA, '--isolate', '--mode', 'container',
                                  '--root', str(root), '-v', f'{rw}:/rw', '-v', f'{protected}:/prot',
                                  '--guard-file-access', vector, '--allow-stdio-output', '--allow-stream-input',
                                  '--', './.elf-exec', 'h', 'lazy', str(image2), str(cache3), rel, str(op), '400'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 cwd='/')
            first = p.stdout.readline()
            stop.clear()
            t = threading.Thread(target=mover)
            t.start()
            try:
                out, err = p.communicate('go\n', timeout=300)
            finally:
                stop.set()
                t.join()
            got = {int(x.split()[1]): int(x.split()[2]) for x in out.splitlines() if x.startswith('lazy-rc ')}
            results[(rel, op)] = got if first == 'ready\n' and got else first + out + err
        ok = all(isinstance(g, dict) and sum(g.values()) == 400 and 0 not in g and EACCES in g
                 for g in results.values())
        check(f'{vector}: a protected subtree moved into the cache after the check is refused where met',
              ok, results)
        check(f'{vector}: protected unchanged while moved in and out (names, contents, metadata)',
              snapshot(protected) == before, sorted(snapshot(protected)))

if failures:
    print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
    sys.exit(1)
print('lazy nested acceptance: all passed')
