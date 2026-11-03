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
not there) and protected stays as it was.

Marker link: while forged requests expand /many (300 entries) over and
over, the host removes the completion marker and puts a symlink in its
place pointing to a path outside every tree. Expected: the outside path
is never created; a request either finds the marker there (0) or
refuses the link (ELOOP).

Also (docs/REVIEW_FIX_TESTS.md T-R1-05 to T-R1-08): a link put at a made
directory's temporary name never takes its chmod; a name the host makes
meanwhile is never replaced; a fill never writes a file renamed over the
placeholder after its check; a lower's cache (--lower-image, a forged
BROKER_LAZY_PATH) is held to the same rules, moved-in subtrees included."""
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

    # A symlink put at the completion marker during expansions.
    image3 = tmp / 'rw' / 'img3.erofs'
    w = erofs.Writer(image3)
    try:
        w.put(['many'], erofs.Node(stat.S_IFDIR | 0o755, mtime=1700000000))
        for i in range(300):
            w.put(['many', f'f{i:03}'], erofs.Node(stat.S_IFREG | 0o644, mtime=1700000000))
        w.finish(1700000000)
    finally:
        w.close()
    cache4 = rw / 'cache4'
    cache4.mkdir()
    erofs.expand(image3, cache4, '')
    secret = tmp / 'secret'
    secret.mkdir()
    sentinel = secret / 'created-by-marker'
    marker = cache4 / 'many' / '.wh..elf-lazy'
    stop = threading.Event()

    def planter():
        while not stop.is_set():
            try:
                if marker.is_file() and not marker.is_symlink():
                    marker.unlink()
                time.sleep(0.0003)
                os.symlink(sentinel, marker)
                time.sleep(0.0003)
                marker.unlink()
            except OSError:
                pass
    p = subprocess.Popen([str(loader), *lib.ISOLATE_EXTRA, '--isolate', '--mode', 'container',
                          '--root', str(root), '-v', f'{rw}:/rw', '-v', f'{protected}:/prot',
                          '--guard-file-access', 'dwr', '--allow-stdio-output', '--allow-stream-input',
                          '--', './.elf-exec', 'h', 'lazy', str(image3), str(cache4), '/many', '0', '400'],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd='/')
    first = p.stdout.readline()
    t = threading.Thread(target=planter)
    t.start()
    try:
        out, err = p.communicate('go\n', timeout=300)
    finally:
        stop.set()
        t.join()
    got = {int(x.split()[1]): int(x.split()[2]) for x in out.splitlines() if x.startswith('lazy-rc ')}
    check('a symlink at the completion marker never creates the path it points to',
          first == 'ready\n' and sum(got.values()) == 400 and set(got) <= {0, -40} and
          not os.path.lexists(sentinel) and not os.listdir(secret), [got, first + out[-300:] + err[-300:]])

    def guest(args, probe_args, mutate=None):
        """The probe in a guest. With mutate: N-request mode, mutate(stop) on
        a host thread from the guest's "ready" until it is done; returns
        ({rc: count} or None, output). Without: (rc or None, output)."""
        cmd = [str(loader), *lib.ISOLATE_EXTRA, '--isolate', '--mode', 'container', *args,
               '--allow-stdio-output', '--allow-stream-input', '--', './.elf-exec', 'h', *probe_args]
        if mutate is None:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd='/')
            for line in r.stdout.splitlines():
                if line.startswith('lazy '):
                    return int(line.split()[1]), r.stdout + r.stderr
            return None, r.stdout + r.stderr
        r = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, cwd='/')
        first = r.stdout.readline()
        halt = threading.Event()
        th = threading.Thread(target=mutate, args=(halt,))
        th.start()
        try:
            o, e = r.communicate('go\n', timeout=300)
        finally:
            halt.set()
            th.join()
        counts = {int(x.split()[1]): int(x.split()[2]) for x in o.splitlines() if x.startswith('lazy-rc ')}
        return (counts if first == 'ready\n' and counts else None), first + o[-600:] + e[-600:]

    def make_image(path, entries):
        w = erofs.Writer(path)
        try:
            for parts, mode, data in entries:
                node = erofs.Node(mode, mtime=1700000000)
                if data is not None:
                    w.write_data(node, [data])
                w.put(parts, node)
            w.finish(1700000000)
        finally:
            w.close()

    def file_state(path):
        st = os.lstat(path)
        return st.st_mode, st.st_size, st.st_mtime_ns, path.read_bytes()

    # T-R1-05: the mode of a directory just made never goes through a link
    # put at its temporary name before the chmod.
    image5 = rw / 'img5.erofs'
    make_image(image5, [(['d'], stat.S_IFDIR | 0o755, None)] +
               [(['d', f's{i:03}'], stat.S_IFDIR | 0o755, None) for i in range(200)])
    cache5 = rw / 'cache5'
    cache5.mkdir()
    erofs.expand(image5, cache5, '')
    secret5 = tmp / 'secret5'
    secret5.mkdir()
    sentinel5 = secret5 / 'sentinel'
    sentinel5.write_bytes(b'sentinel 5\n')
    os.chmod(sentinel5, 0o600)
    before5 = file_state(sentinel5)
    d5 = cache5 / 'd'
    swaps = [0]

    def swapper(halt):
        tmpname, marker5 = d5 / '.wh..elf-lazy-tmp', d5 / '.wh..elf-lazy'
        while not halt.is_set():
            try:
                os.rmdir(tmpname)       # made, its chmod maybe still to come
                os.symlink(sentinel5, tmpname)
                swaps[0] += 1
            except OSError:
                pass
            if os.path.isfile(marker5) and not os.path.islink(marker5):
                for n in os.listdir(d5):  # expanded: undone, to be expanded again
                    q = d5 / n
                    try:
                        os.rmdir(q) if q.is_dir() and not q.is_symlink() else os.unlink(q)
                    except OSError:
                        pass
    got, out = guest(['--root', str(root), '-v', f'{rw}:/rw', '-v', f'{protected}:/prot',
                      '--guard-file-access', 'dwr'],
                     ['lazy', str(image5), str(cache5), '/d', '0', '400'], swapper)
    check('a link put at a made directory before its chmod never changes what it points to',
          got is not None and sum(got.values()) == 400 and file_state(sentinel5) == before5 and
          os.listdir(secret5) == ['sentinel'], [got, swaps[0], out])
    print('  (temporary names swapped for a link:', swaps[0], ')')

    # T-R1-07: a fill writes only the placeholder it checked and locked, not
    # a file renamed over its name in between.
    image6 = rw / 'img6.erofs'
    make_image(image6, [(['f'], stat.S_IFREG | 0o644, b'I' * 65536)])
    cache6, kept6 = rw / 'cache6', rw / 'victims6'
    cache6.mkdir()
    kept6.mkdir()
    erofs.expand(image6, cache6, '')
    stock6 = rw / 'stock6'
    shutil.copy2(cache6 / 'f', stock6)   # a placeholder (its atime mark) to put back each round
    victim = b'victim, not to be written\n'

    def renamer(halt):
        i = 0
        while not halt.is_set():
            try:
                shutil.copy2(stock6, cache6 / '.p')
                os.rename(cache6 / '.p', cache6 / 'f')
                time.sleep(0.0003)
                v = cache6 / f'.v{i}'
                v.write_bytes(victim)
                os.chmod(v, 0o644)
                os.rename(v, cache6 / 'f')
                time.sleep(0.0003)
                os.rename(cache6 / 'f', kept6 / f'v{i}')
                i += 1
            except OSError:
                pass
    got, out = guest(['--root', str(root), '-v', f'{rw}:/rw', '-v', f'{protected}:/prot',
                      '--guard-file-access', 'dwr'],
                     ['lazy', str(image6), str(cache6), '/f', '1', '400'], renamer)
    victims = sorted(kept6.iterdir())
    changed = [v.name for v in victims if v.read_bytes() != victim]
    check('a fill never writes a file renamed over the placeholder after its check',
          got is not None and sum(got.values()) == 400 and set(got) <= {0, -2, -11} and
          victims and not changed, [got, len(victims), changed[:5], out])
    print('  (files renamed over the placeholder:', len(victims), ')')

    # T-R1-08: a lower's cache (--lower CACHE --lower-image IMAGE, the
    # BROKER_LAZY_PATH request) is held to the same rule.
    upper = tmp / 'upper8'
    upper.mkdir()
    shutil.copy2(probe, upper / '.elf-exec')

    def lower_args(cache_dir, img, binds, vector):
        return ['--root', str(upper), '--lower', str(cache_dir), '--lower-image', str(img),
                '--mount-table', str(tmp / 'mounts8'), '--mount-scratch', str(tmp / 'scratch8'),
                *binds, '--guard-file-access', vector]
    lower7, lower8 = tmp / 'lower7', tmp / 'lower8'
    for c in (lower7, lower8):
        c.mkdir()
        erofs.expand(image, c, '')
    erofs.expand(image, lower7, 'protected')
    os.unlink(lower7 / 'protected' / 'new')
    for vector in ('dr', 'dd'):
        before = snapshot(lower7 / 'protected')
        for rel, op, what in (('/protected', 0, 'expand protected'), ('', 0, 'expand the cache root'),
                              ('/protected/a', 1, 'fill protected/a')):
            rc, out = guest(lower_args(lower7, image, ['-v', f'{lower7}/protected:/prot'], vector),
                            ['lazypath', f'{lower7}{rel}', str(op)])
            check(f'{vector}: lower cache: {what} inside a protected subtree is refused', rc == EACCES, out)
        check(f'{vector}: lower cache: protected unchanged (names, contents, metadata)',
              snapshot(lower7 / 'protected') == before, sorted(snapshot(lower7 / 'protected')))
    rc, out = guest(lower_args(lower8, image, [], 'd'), ['lazypath', f'{lower8}/protected', '0'])
    check('lower cache: with nothing protected inside it still expands',
          rc == 0 and (lower8 / 'protected' / 'a').exists(), out)

    lower9, outside9 = tmp / 'lower9', tmp / 'outside9'
    lower9.mkdir()
    outside9.mkdir()
    for rel in ('', 'holder', 'holder/protected'):
        erofs.expand(image2, lower9, rel)
    os.unlink(lower9 / 'holder' / 'protected' / 'new')
    os.unlink(lower9 / 'holder' / 'protected' / '.wh..elf-lazy')
    os.rename(lower9 / 'holder', outside9 / 'holder')
    protected9 = outside9 / 'holder' / 'protected'

    def mover9(halt):
        while not halt.is_set():
            os.rename(outside9 / 'holder', lower9 / 'holder')
            time.sleep(0.0005)
            os.rename(lower9 / 'holder', outside9 / 'holder')
            time.sleep(0.0005)
    for vector in ('dr', 'dd'):
        before = snapshot(protected9)
        results = {}
        for rel, op in (('/holder/protected', 0), ('/holder/protected/a', 1)):
            got, out = guest(lower_args(lower9, image2, ['-v', f'{protected9}:/prot'], vector),
                             ['lazypath', f'{lower9}{rel}', str(op), '400'], mover9)
            results[(rel, op)] = got if got else out
        ok = all(isinstance(g, dict) and sum(g.values()) == 400 and 0 not in g and EACCES in g
                 for g in results.values())
        check(f'{vector}: lower cache: a protected subtree moved in after the check is refused where met',
              ok, results)
        check(f'{vector}: lower cache: protected unchanged while moved in and out',
              snapshot(protected9) == before, sorted(snapshot(protected9)))

    # T-R1-06: a name made by someone else while the expansion runs is never
    # replaced by the expansion's own (RENAME_NOREPLACE; storage without it
    # replaces, so the case is not applicable there).
    def noreplace_supported(where):
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        a, b = where / '.nr-a', where / '.nr-b'
        a.write_bytes(b'a')
        b.write_bytes(b'b')
        rc = libc.syscall(276, -100, bytes(a), -100, bytes(b), 1)   # renameat2 (aarch64)
        err = ctypes.get_errno()
        for q in (a, b):
            if q.exists():
                q.unlink()
        return rc < 0 and err == 17
    if not noreplace_supported(rw):
        print('SKIP: the storage has no RENAME_NOREPLACE; a name made meanwhile is replaced there')
    else:
        image10 = rw / 'img10.erofs'
        make_image(image10, [(['d'], stat.S_IFDIR | 0o755, None)] +
                   [(['d', f'f{i:03}'], stat.S_IFREG | 0o644, b'image\n') for i in range(200)])
        cache10 = rw / 'cache10'
        cache10.mkdir()
        erofs.expand(image10, cache10, '')
        d10 = cache10 / 'd'
        lost, made = [], [0]

        def claimer(halt):
            marker10 = d10 / '.wh..elf-lazy'
            while not halt.is_set():
                for n in os.listdir(d10):   # undone, to be expanded again
                    try:
                        os.unlink(d10 / n)
                    except OSError:
                        pass
                mine = {}
                for i in reversed(range(200)):  # from the end: met in the middle
                    q = d10 / f'f{i:03}'
                    try:
                        fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    except OSError:
                        continue
                    os.write(fd, b'host\n')
                    mine[q] = os.fstat(fd).st_ino
                    os.close(fd)
                made[0] += len(mine)
                for _ in range(200):
                    if os.path.lexists(marker10) or halt.is_set():
                        break
                    time.sleep(0.001)
                for q, ino in mine.items():
                    try:
                        st = os.lstat(q)
                        ok = st.st_ino == ino and q.read_bytes() == b'host\n'
                    except OSError:
                        ok = False
                    if not ok:
                        lost.append(q.name)
        got, out = guest(['--root', str(root), '-v', f'{rw}:/rw', '-v', f'{protected}:/prot',
                          '--guard-file-access', 'dwr'],
                         ['lazy', str(image10), str(cache10), '/d', '0', '400'], claimer)
        check('a name made meanwhile is never replaced by the expansion (and no temporary name is left)',
              got is not None and sum(got.values()) == 400 and not lost and
              not os.path.lexists(d10 / '.wh..elf-lazy-tmp'), [got, made[0], lost[:5], out])
        print('  (names made by the host meanwhile:', made[0], ')')

if failures:
    print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
    sys.exit(1)
print('lazy nested acceptance: all passed')
