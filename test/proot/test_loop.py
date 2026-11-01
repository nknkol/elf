#!/usr/bin/env python3
"""mount -o loop of a read-only image (docs/OCI.md, R6): with
--emulate-mounts the loop devices /dev/loop-control and /dev/loop0..7 are
emulated and a loop mount of an erofs image (tools/oci/erofs.py) is a
read-only view of the image, expanded on demand into the mount scratch.

Expected (Alpine's BusyBox mount and losetup): `mount -o loop IMAGE DIR`
binds the first free device and shows the image's files, symlinks and
programs; /proc/mounts lists /dev/loop0 as erofs ro; a child sees the
mount; writes are refused where the build enforces mount access (the
guarded one); losetup -f, losetup DEV FILE, losetup DEV, mount -t erofs DEV
and losetup -d work; umount frees an auto-clearing device; a file that is
not an image does not mount. Only what was read is filled; the image file
is unchanged. Both builds, plain and with --isolate."""
import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
sys.path.insert(0, str(lib.REPO / 'tools/oci'))
import erofs  # noqa: E402

ALPINE = lib.require(lib.ALPINE)

STEPS = [
    ('mount -o loop', 'mount -o loop /w/img.erofs /w/mnt && cat /w/mnt/hello.txt /w/mnt/link && '
     'ls /w/mnt && /w/mnt/bin/tool && md5sum /w/mnt/big | cut -c1-32', None),
    ('/proc/mounts', 'grep " /w/mnt " /proc/mounts | cut -d" " -f1,3,4 | cut -d, -f1', '/dev/loop0 erofs ro\n'),
    ('child sees it', 'sh -c "cat /w/mnt/sub/inner"', 'inner\n'),
    ('read-only', 'echo x > /w/mnt/new 2>/dev/null && echo written || echo refused', None),
    ('losetup -f', 'losetup -f', '/dev/loop1\n'),
    ('losetup DEV FILE, mount -t erofs DEV', 'losetup /dev/loop1 /w/img.erofs && losetup /dev/loop1 | '
     'grep -c img.erofs && mount -t erofs -o ro /dev/loop1 /w/mnt2 && cat /w/mnt2/sub/inner && '
     'umount /w/mnt2 && losetup -d /dev/loop1 && losetup -f', '1\ninner\n/dev/loop1\n'),
    ('umount frees the device', 'umount /w/mnt && ls /w/mnt | wc -l && losetup -f', '0\n/dev/loop0\n'),
    ('not an image', 'mount -o loop /w/plain /w/mnt 2>/dev/null && echo mounted || echo refused; '
     'losetup -f', 'refused\n/dev/loop0\n'),
]

with tempfile.TemporaryDirectory(prefix='loop-', dir=lib.mode_capable()) as tmp:
    big = os.urandom(300000)
    w = erofs.Writer(Path(tmp, 'img.erofs'))
    try:
        def add(path, mode, data=b''):
            node = erofs.Node(mode, mtime=1700000000)
            parts = path.split('/')
            if stat.S_ISLNK(mode):
                node.target = data
                node.size = len(data)
            elif stat.S_ISREG(mode):
                w.write_data(node, [data])
            w.put(parts, node)
        add('hello.txt', stat.S_IFREG | 0o644, b'hello\n')
        add('link', stat.S_IFLNK | 0o777, b'hello.txt')
        add('sub', stat.S_IFDIR | 0o755)
        add('sub/inner', stat.S_IFREG | 0o644, b'inner\n')
        add('sub/unread', stat.S_IFREG | 0o644, b'never read\n')
        add('bin', stat.S_IFDIR | 0o755)
        add('bin/tool', stat.S_IFREG | 0o755, b'#!/bin/sh\necho tool\n')
        add('big', stat.S_IFREG | 0o644, big)
        w.finish(1700000000)
    finally:
        w.close()
    image_bytes = Path(tmp, 'img.erofs').read_bytes()
    with erofs.Image(Path(tmp, 'img.erofs')) as img:   # what the writer made reads back
        assert img.read(img.lookup('big')) == big
    for suffix, loader in lib.loaders():
        for isolate in ([], ['--isolate']):
            what = (loader.name, isolate)
            work = Path(tmp, 'w' + suffix + ''.join(isolate))
            (work / 'mnt').mkdir(parents=True)
            (work / 'mnt2').mkdir()
            (work / 'img.erofs').write_bytes(image_bytes)
            (work / 'plain').write_bytes(b'\0' * 8192)
            scratch = Path(tmp, 'scratch' + suffix + ''.join(isolate))
            guard = ['--guard-path-mutations', 'rww'] if suffix else []
            for name, command, expected in STEPS:
                p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container',
                                    '--root', str(ALPINE), '-v', f'{work}:/w', '-v', '/dev/null:/dev/null',
                                    *guard, '--mount-table', str(work) + '.mounts', '--mount-scratch',
                                    str(scratch), '--', 'bin/busybox', 'sh', '-c',
                                    'PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; ' + command],
                                   cwd='/', capture_output=True, text=True, timeout=60)
                if name == 'mount -o loop':
                    expected = ('hello\nhello\nbig\nbin\nhello.txt\nlink\nsub\ntool\n' +
                                hashlib.md5(big).hexdigest() + '\n')
                if name == 'read-only':
                    expected = 'refused\n' if suffix else p.stdout   # (the plain build shows ro only)
                assert p.returncode == 0 and p.stdout == expected, (what, name, p.returncode, p.stdout,
                                                                    p.stderr[-2000:])
            assert (work / 'img.erofs').read_bytes() == image_bytes, (what, 'the image changed')
            assert not (work / 'mnt' / 'new').exists(), (what, 'a write reached the mountpoint')
            # The cache in the mount scratch: what was read is filled, the rest
            # stays placeholders.
            caches = [Path(d) for d, _, fs in os.walk(scratch) if 'hello.txt' in fs]
            assert caches, (what, 'no cache in the mount scratch', list(os.walk(scratch))[:5])
            # (Each mount has a cache of its own; the first one read big.)
            assert any(not erofs.placeholder(os.lstat(c / 'big')) and (c / 'big').read_bytes() == big
                       for c in caches), (what, 'big was read')
            for cache in caches:
                assert erofs.placeholder(os.lstat(cache / 'sub' / 'unread')), (what, 'unread stays a placeholder')
            print('PASS: mount -o loop of an erofs image (losetup, /proc/mounts, autoclear, on demand):',
                  loader.name, *isolate)
