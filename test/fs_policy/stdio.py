#!/usr/bin/env python3
"""Explicit stdio output: real type checks, dup/exec lifecycle, no file grants."""
import hashlib
import json
import os
import select
import socket
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']
with tempfile.TemporaryDirectory(prefix='stdio-guard-', dir=build) as tmp:
    root = Path(tmp)
    (root / 'ro').mkdir()
    (root / 'ro/file').write_bytes(b'unchanged')
    subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', str(repo / 'test/fs_policy/stdio.c'),
                    '-o', str(root / 'probe')], check=True)
    base = [str(loader), '--mode', 'container', '--root', str(root),
            '-v', f'{root}/ro:/ro', '--guard-file-mutations', 'dr']
    def run(mode, *, allow=True, output=subprocess.PIPE, data=None):
        p = subprocess.run([*base, *(['--allow-stdio-output'] if allow else []),
                            '--', './probe', mode], cwd=root, input=data,
                           stdout=output, stderr=subprocess.PIPE, timeout=20)
        assert p.returncode == 0, (mode, p.returncode, p.stdout, p.stderr)
        return p
    p = run('pipe', data=b'R')
    assert p.stdout == b'ABDQFC' and b'\nSTDIO-E\n' in p.stderr, (p.stdout, p.stderr)
    assert (root / 'ro/file').read_bytes() == b'unchanged'
    assert run('denied', allow=False).stdout == b''
    target = root / 'redirected'
    target.write_bytes(b'unchanged')
    with target.open('r+b') as f:
        run('denied', output=f)
    assert target.read_bytes() == b'unchanged'
    with open('/dev/null', 'wb') as f:
        run('denied', output=f)
    left, right = socket.socketpair()
    try:
        run('denied', output=left)
        right.setblocking(False)
        try:
            assert right.recv(10) == b''
        except BlockingIOError:
            pass
    finally:
        left.close();right.close()
    readfd, writefd = os.pipe()
    try:
        run('denied', output=readfd)
    finally:
        os.close(readfd);os.close(writefd)
    print('PASS: pipe stdio, stdin, writev, dup/fork/exec, slot reuse and regular/socket/non-TTY rejection')
    try:
        master, slave = os.openpty()
    except OSError as exc:
        print('SKIP: native PTY unavailable:', exc)
    else:
        try:
            run('basic', output=slave)
            assert select.select([master], [], [], 2)[0], 'no PTY output'
            assert os.read(master, 32) in (b'ok\n', b'ok\r\n')
            print('PASS: verified terminal stdio output')
        finally:
            os.close(master);os.close(slave)
    for args, marker in (([str(loader), '--allow-stdio-output', '--', str(root / 'probe')],
                          b'stdio output requires file mutation guard'),
                         ([*base, '--allow-stdio-output', '--allow-stdio-output', '--', './probe'],
                          b'duplicate stdio output option')):
        p = subprocess.run(args, cwd=root, capture_output=True, timeout=20)
        assert p.returncode != 0 and marker in p.stdout+p.stderr, (p.stdout, p.stderr)
    print('PASS: invalid stdio option combinations rejected')

# Optional libc/rootfs smoke through actual protected shell and exec chains.
for directory, shell, args, marker in (
        ('alpine-test-root', './bin/busybox',
         ['sh', '-c', 'read value; printf "%s\\n" "$value"; exec /bin/busybox cat /etc/alpine-release'], '3.24.3'),
        ('ubuntu-root', './usr/bin/dash',
         ['-c', 'read value; printf "%s\\n" "$value"; exec /usr/bin/cat /etc/os-release'], 'Ubuntu')):
    root = build / directory
    if not (root / shell).exists():
        print('SKIP: protected stdio rootfs unavailable:', directory)
        continue
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                        '--guard-file-mutations', 'r', '--allow-stdio-output',
                        '--', shell, *args], cwd=root, input='STDIO-INPUT\n',
                       text=True, capture_output=True, timeout=20)
    assert p.returncode == 0 and 'STDIO-INPUT\n' in p.stdout and marker in p.stdout, (
        directory, p.returncode, p.stdout, p.stderr)
    print('PASS: protected stdio read/printf/exec with', directory)
