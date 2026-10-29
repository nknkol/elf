#!/usr/bin/env python3
"""Explicit output grants for locally created sockets, eventfds and memfds."""
import hashlib
import json
import os
import socket
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']
with tempfile.TemporaryDirectory(prefix='local-output-', dir=build) as tmp:
    root = Path(tmp)
    (root / 'rw').mkdir()
    (root / 'rw/file').write_bytes(b'seed')
    subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', str(repo / 'test/fs_policy/local_output.c'),
                    '-o', str(root / 'probe')], check=True)
    base = [str(loader), '--mode', 'container', '--root', str(root), '-v', f'{root}/rw:/rw']
    for mode, extra in (('on', ['--allow-local-output']), ('off', [])):
        inherited, peer = socket.socketpair()
        os.dup2(inherited.fileno(), 10)
        try:
            p = subprocess.run([*base, '--guard-file-mutations', 'rw', *extra, '--', './probe', mode],
                               cwd=root, capture_output=True, pass_fds=(10,), timeout=30)
        finally:
            os.close(10)
            inherited.close()
        assert p.returncode == 0, (mode, p.returncode, p.stdout, p.stderr)
        peer.setblocking(False)
        try:
            leaked = peer.recv(16)
        except BlockingIOError:
            leaked = b''
        peer.close()
        assert leaked == b'', leaked
        assert (root / 'rw/file').read_bytes() == b'seed'
        print('PASS: local socket/eventfd/memfd output, dup/fork/exec and existing contracts:', mode)
    p = subprocess.run([*base, '--allow-local-output', '--', './probe', 'on'],
                       cwd=root, capture_output=True, text=True, timeout=20)
    assert p.returncode != 0 and 'local output requires file mutation guard' in p.stdout + p.stderr
    p = subprocess.run([*base, '--guard-file-mutations', 'rw', '--allow-local-output',
                        '--allow-local-output', '--', './probe', 'on'],
                       cwd=root, capture_output=True, text=True, timeout=20)
    assert p.returncode != 0 and 'duplicate local output option' in p.stdout + p.stderr
    print('PASS: invalid local output option combinations rejected')
