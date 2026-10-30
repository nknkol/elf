#!/usr/bin/env python3
"""Real rootfs file workflows, including shallow and nested archive extraction."""
from pathlib import Path
import subprocess
import tempfile
import tarfile
import os
import errno

build = Path(__file__).resolve().parents[2] / 'build'
loader = build / 'elfloader-guarded'
for directory, shell, prefix in (
        ('alpine-test-root', './bin/busybox', ['sh']),
        ('ubuntu-root', './usr/bin/dash', [])):
    root = build / directory
    if not (root / shell).exists():
        print('SKIP: optional file workflows', directory)
        continue
    with tempfile.TemporaryDirectory(prefix='file-workflow-', dir=build) as temp:
        def run(command):
            return subprocess.run(
                [str(loader), '--mode', 'container', '--root', str(root),
                 '-v', f'{temp}:/work', '-v', '/dev/null:/dev/null', '--',
                 shell, *prefix, '-c', 'export PATH=/bin:/usr/bin; set -e; ' + command],
                cwd=root, capture_output=True, text=True, timeout=20)

        cases = [
            ('list', 'ls /etc/os-release', ['/etc/os-release']),
            ('copy-rename', 'mkdir /work/a; printf payload >/work/a/file; '
             'cp /work/a/file /work/copy; mv /work/copy /work/moved; cat /work/moved', ['payload']),
            ('symlink', 'ln -s a/file /work/link; readlink /work/link; readlink -f /work/link',
             ['a/file', '/work/a/file']),
            ('find', 'find /work -type f', ['/work/a/file', '/work/moved']),
            ('tar-create', 'tar -cf /work/archive.tar -C /work a', []),
            ('tar-list', 'tar -tf /work/archive.tar', ['a/', 'a/file']),
        ]
        for name, command, expected in cases:
            p = run(command)
            assert p.returncode == 0 and sorted(p.stdout.splitlines()) == sorted(expected), (
                directory, name, p.returncode, p.stdout, p.stderr)
            print('PASS: file workflow', directory, name)
        assert (Path(temp) / 'moved').read_text() == 'payload'
        assert not (Path(temp) / 'copy').exists()
        p = run('mkdir /work/extracted; tar -xf /work/archive.tar -C /work/extracted; '
                'cat /work/extracted/a/file')
        assert (p.returncode, p.stdout) == (0, 'payload'), (p.returncode, p.stdout, p.stderr)
        assert (Path(temp) / 'extracted/a/file').read_text() == 'payload'
        print('PASS: file workflow', directory, 'tar-extract')
        p = run('mkdir -p /work/a/sub; printf nested >/work/a/sub/deep; '
                'tar -cf /work/nested.tar -C /work a; mkdir /work/deep-extracted; '
                'tar -xf /work/nested.tar -C /work/deep-extracted; '
                'cat /work/deep-extracted/a/sub/deep')
        assert (p.returncode, p.stdout) == (0, 'nested'), (p.returncode, p.stdout, p.stderr)
        assert (Path(temp) / 'deep-extracted/a/sub/deep').read_text() == 'nested'
        print('PASS: file workflow', directory, 'tar-extract-nested')

        # Inspect archive bytes on the host, independently of guest tar listing.
        for name, command, member in (
                ('absolute', 'tar -cf /work/absolute.tar /work/a', 'work/a/file'),
                ('gzip', 'tar -czf /work/gzip.tar -C /work a', 'a/file'),
                ('dot', 'tar -cf /work/dot.tar -C /work/a .', './file'),
                ('links', 'ln -s file /work/a/sym; '
                 'tar -cf /work/links.tar -C /work a', 'a/file')):
            p = run(command)
            assert p.returncode == 0, (directory, name, p.returncode, p.stdout, p.stderr)
            with tarfile.open(Path(temp) / (name + '.tar'), 'r:*') as archive:
                assert archive.extractfile(member).read() == b'payload'
                if name == 'links':
                    assert archive.getmember('a/sym').issym()
                    assert archive.getmember('a/sym').linkname == 'file'
            print('PASS: file workflow', directory, 'tar-pack-' + name)
        # Hardlink creation is denied by this host filesystem even natively.
        # Do not disguise that restriction as a successful guest link test.
        try:
            os.link(Path(temp) / 'a/file', Path(temp) / 'a/hard')
        except OSError as error:
            if error.errno not in (errno.EPERM, errno.EACCES, errno.EOPNOTSUPP):
                raise
            print('SKIP: tar hardlink fixture denied natively', directory, error.errno)
        else:
            p = run('tar -cf /work/hardlinks.tar -C /work a')
            assert p.returncode == 0, (directory, p.returncode, p.stdout, p.stderr)
            with tarfile.open(Path(temp) / 'hardlinks.tar') as archive:
                assert archive.extractfile('a/hard').read() == b'payload'
                assert any(archive.getmember(n).islnk() for n in ('a/file', 'a/hard'))
            print('PASS: file workflow', directory, 'tar-pack-hardlinks')
