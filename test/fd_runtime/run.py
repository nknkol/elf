#!/usr/bin/env python3
"""End-to-end FD experiment through the built loader, not linked model callbacks."""
import ctypes
import fcntl
import os
import socket
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']
# Compare status flags against this host: it may inherit O_NONBLOCK on accept.
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
accept_nonblock = 0
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_NONBLOCK |
                   socket.SOCK_CLOEXEC) as listener:
    listener.bind('')
    listener.listen(4)
    for mode in range(3):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(listener.getsockname())
            flags = socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK if mode == 1 else 0
            accepted = libc.syscall(202 if mode == 0 else 242,
                                    listener.fileno(), 0, 0, flags)
            assert accepted >= 0, ('native accept', mode, ctypes.get_errno())
            try:
                assert fcntl.fcntl(accepted, fcntl.F_GETFD) == (fcntl.FD_CLOEXEC if mode == 1 else 0)
                if fcntl.fcntl(accepted, fcntl.F_GETFL) & os.O_NONBLOCK:
                    accept_nonblock |= 1 << mode
            finally:
                os.close(accepted)
print('Native accept/accept4 nonblocking mask:', accept_nonblock)
with tempfile.TemporaryDirectory(prefix='fd-runtime-', dir=build) as temp:
    work = Path(temp)
    probe = work / 'probe'
    (work / 'fd-data').write_text('Q runtime file\n')
    subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector',
                    '-DEXPECT_ACCEPT_NONBLOCK=' + str(accept_nonblock),
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_runtime/probe.c'), '-o', str(probe)], check=True)
    p = subprocess.run([str(loader), '--mode', 'compat', '--', str(probe)],
                       cwd=work, text=True, capture_output=True, timeout=20)
    assert p.returncode == 0 and 'PASS: runtime FD' in p.stdout, (p.returncode,p.stdout,p.stderr)
    print(p.stdout, end='')

# Optional smoke tests against already extracted user-provided fixtures.
for directory, target, arguments, marker in [
        ('alpine-test-root', './bin/busybox', ['cat', '/etc/alpine-release'], '3.24.3'),
        ('ubuntu-root', './usr/bin/cat', ['/etc/os-release'], 'Ubuntu')]:
    root = build / directory
    if not (root / target).exists():
        print('SKIP: optional rootfs smoke', directory)
        continue
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                        '--', target, *arguments], cwd=root, text=True,
                       capture_output=True, timeout=20)
    assert p.returncode == 0 and marker in p.stdout, (directory, p.returncode, p.stdout, p.stderr)
    print('PASS: experimental runtime rootfs cat', directory)
