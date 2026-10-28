#!/usr/bin/env python3
"""Real rootfs file workflows, including shallow and nested archive extraction."""
from pathlib import Path
import subprocess
import tempfile

build = Path(__file__).resolve().parents[2] / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
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
