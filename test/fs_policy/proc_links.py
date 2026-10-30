#!/usr/bin/env python3
"""/proc links in guest terms (PRoot readlink_proc semantics), both backends."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: /proc link rootfs unavailable:', alpine)
    raise SystemExit(0)


def loader(suffix):
    path = build / f'elfloader{suffix}'
    manifest = json.loads((build / f'elfloader{suffix}.json').read_text())
    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sha256']
    return path


SCRIPT = r'''
cd /etc
echo "exe=$(readlink /proc/self/exe)"
echo "cwd=$(readlink /proc/self/cwd)"
echo "root=$(readlink /proc/self/root)"
echo "thread=$(readlink /proc/thread-self/cwd)"
echo "real=$(realpath /proc/self/cwd)"
echo "fd0=$(readlink /proc/self/fd/0 < /etc/alpine-release)"
echo "via=$(cat /proc/self/fd/0 < /etc/alpine-release)"
echo "pipe=$(readlink /proc/self/fd/1 | cut -c1-5)"
echo "cmd=$(cat /proc/self/cmdline | tr '\0' ' ')"
echo "fds=$(ls /proc/self/fd | wc -l)"
echo "script=$(/work/exe.sh)"
echo "chain=$(sh -c 'exec /bin/busybox readlink /proc/self/exe')"
echo "outside=$(readlink /proc/self/fd/9 2>/dev/null || echo refused)"
echo "comm=$(cat /proc/self/comm)"
echo "other=$(sh -c 'readlink /proc/$PPID/exe' & wait)"
'''

with tempfile.TemporaryDirectory(prefix='proc-links-', dir=build) as tmp:
    work = Path(tmp)
    script = work / 'exe.sh'
    script.write_text('#!/bin/sh\nreadlink /proc/$$/exe\n')
    script.chmod(0o755)
    hidden = Path(tempfile.mkdtemp(prefix='proc-outside-', dir=build))
    outside = hidden / 'outside-view'
    outside.write_text('host only\n')
    release = (alpine / 'etc/alpine-release').read_text().strip()
    for suffix, options, guarded in (
            ('', [], False),
            ('-guarded', [], False),
            ('-guarded', ['--guard-file-access', 'rrww', '--allow-stdio-output',
                                '--allow-pipe-output', '--allow-local-output',
                                '--allow-stream-input', '--revalidate-file-fds'], True)):
        fd = os.open(outside, os.O_RDONLY)
        os.dup2(fd, 9)
        try:
            p = subprocess.run([str(loader(suffix)), '--mode', 'container', '--root', str(alpine),
                                '-v', '/proc:/proc', '-v', f'{work}:/work', '-v', '/dev/null:/dev/null',
                                *options, '--', './bin/busybox', 'sh', '-c', SCRIPT],
                               cwd=alpine, capture_output=True, text=True, pass_fds=(9,), timeout=60)
        finally:
            os.close(fd)
            os.close(9)
        assert p.returncode == 0, (suffix, guarded, p.returncode, p.stdout, p.stderr[-2000:])
        values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
        expected = {'exe': '/bin/busybox', 'cwd': '/etc', 'root': '/', 'thread': '/etc',
                    'real': '/etc', 'fd0': '/etc/alpine-release', 'via': release,
                    'pipe': 'pipe:', 'script': '/bin/busybox', 'chain': '/bin/busybox',
                    # Outside the view: PRoot keeps the host name; the read guard refuses it.
                    'outside': 'refused' if guarded else str(outside),
                    # comm comes from the exec'd name (the cat symlink), not busybox.
                    'comm': 'cat', 'other': '/bin/busybox'}
        for key, value in expected.items():
            assert values.get(key) == value, (suffix, guarded, key, values.get(key), p.stdout)
        # Guest argv only: no loader options or host paths.
        assert values['cmd'] == 'cat /proc/self/cmdline ', values['cmd']
        assert 'loader' not in values['cmd'] and str(build) not in p.stdout.replace(str(outside), ''), p.stdout
        assert int(values['fds']) >= 3, values['fds']
        print('PASS: /proc links in guest terms:', 'elfloader' + suffix,
              'guarded' if guarded else 'plain')
    shutil.rmtree(hidden)
