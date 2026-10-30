#!/usr/bin/env python3
"""Kernel-based regular FD revalidation, including forged snapshot tags."""
import fcntl
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
loader = lib.loader('-guarded')
with tempfile.TemporaryDirectory(prefix='file-revalidate-', dir=build) as tmp:
    work = Path(tmp)
    root = work / 'guest'
    for path in (root, work/'out', work/'ro'):
        path.mkdir()
        (path/'file').write_bytes(b'seed')
    subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', str(repo/'test/fs_policy/revalidate.c'),
                    '-o', str(root/'probe')], check=True)
    base = [str(loader), '--mode', 'container', '--root', str(root),
            '-v', f'{work}/out:/out', '-v', f'{work}/ro:/ro']
    p = subprocess.run([*base, '--guard-file-mutations', 'dwr', '--revalidate-file-fds',
                        '--', './probe', 'start'], cwd=root, capture_output=True, timeout=20)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    assert (work/'out/file').read_bytes() == b'END'
    print('PASS: regular FD write/dup/metadata across two exec calls')

    def injected(path, mode, *, extra=(), policy='dwr', enabled=True, unlink=False):
        fd = os.open(path, os.O_RDWR)
        state = os.memfd_create('untrusted-state', os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC)
        try:
            if unlink:
                path.unlink()
                path.write_bytes(b'replacement')
            # Claimed mount=1/RW, irrespective of actual FD. Seals do not authenticate it.
            os.write(state, struct.pack('<4Q6Q', 0x31534446464c45, 1, 1, 1,
                                        fd, 0, 1, 1, 1, 2))
            fcntl.fcntl(state, fcntl.F_ADD_SEALS,
                        fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
            p = subprocess.run([*base, *extra, '--guard-file-mutations', policy,
                                *(['--revalidate-file-fds'] if enabled else []),
                                '--child-loader', '--fd-state', str(state),
                                '--exec-target', str(root/'probe'), '--exec-path', '/probe',
                                '--', '/probe', mode, str(fd)], cwd=root, pass_fds=(fd,state),
                               capture_output=True, timeout=20)
            assert p.returncode == 0, (mode, p.returncode, p.stdout, p.stderr)
        finally:
            os.close(fd);os.close(state)
    injected(work/'ro/file', 'readonly')
    assert (work/'ro/file').read_bytes() == b'seed'
    (work/'outside').write_bytes(b'outside')
    injected(work/'outside', 'denied')
    assert (work/'outside').read_bytes() == b'outside'
    injected(root/'file', 'denied')
    assert (root/'file').read_bytes() == b'seed'
    injected(work/'out/file', 'denied', enabled=False)
    injected(work/'out/file', 'denied', extra=('-v', f'{work}/out:/alias'), policy='dwrw')
    assert (work/'out/file').read_bytes() == b'END'
    injected(work/'out/file', 'denied', unlink=True)
    assert (work/'out/file').read_bytes() == b'replacement'
    print('PASS: forged RW tags, denied root, disabled option, ambiguous aliases and deleted/replaced inode')

for directory, shell, prefix, cat in (
        ('alpine-test-root', './bin/busybox', ['sh'], '/bin/busybox cat'),
        ('ubuntu-root', './usr/bin/dash', [], '/usr/bin/cat')):
    root = build / directory
    if not (root / shell).exists():
        print('SKIP: redirection rootfs unavailable:', directory)
        continue
    with tempfile.TemporaryDirectory(prefix='redirect-output-', dir=build) as tmp:
        output = Path(tmp)
        command = (f'printf "redirected\\n" | {cat} > /out/result; '
                   f'printf "appended\\n" | {cat} >> /out/result; '
                   f'exec {cat} /out/result')
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                            '-v', f'{output}:/out', '--guard-file-mutations', 'rw',
                            '--allow-stdio-output', '--allow-pipe-output', '--revalidate-file-fds',
                            '--', shell, *prefix, '-c', command], cwd=root,
                           capture_output=True, text=True, timeout=20)
        assert p.returncode == 0 and p.stdout == 'redirected\nappended\n', (
            directory, p.returncode, p.stdout, p.stderr)
        assert (output/'result').read_text() == p.stdout
    print('PASS: protected pipeline file redirection, append and exec:', directory)

for args, marker in ((['--revalidate-file-fds'], 'file FD revalidation requires file mutation guard'),
                     (['--guard-file-mutations', 'r', '--revalidate-file-fds', '--revalidate-file-fds'],
                      'duplicate file FD revalidation option')):
    p = subprocess.run([str(loader), *args, '--', '/no-guest-needed'],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode != 0 and marker in p.stdout+p.stderr, (p.stdout, p.stderr)
print('PASS: invalid file revalidation option combinations rejected')
