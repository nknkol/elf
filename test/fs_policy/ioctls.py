#!/usr/bin/env python3
"""File ioctl authorization, command/type rejection and native parity."""
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']
with tempfile.TemporaryDirectory(prefix='ioctl-policy-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw', 'deny'):
        (root / name).mkdir()
        (root / name / 'file').write_bytes(b'unchanged')
    before = {name: (root / name / 'file').stat().st_ctime_ns for name in ('ro', 'deny')}
    def compile_probe(guarded):
        subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector', *(['-DGUARDED'] if guarded else []),
                        str(repo / 'test/fs_policy/ioctls.c'), '-o', str(root / 'probe.next')], check=True)
        (root / 'probe.next').replace(root / 'probe')
    compile_probe(False)
    native = subprocess.run([str(root / 'probe'), 'native', str(root / 'rw/file')],
                            capture_output=True, timeout=10)
    assert native.returncode == 0 and len(native.stdout)==64, (
        'native ioctl probe', native.returncode, native.stdout, native.stderr)
    print('Native permitted ioctl results:', struct.unpack('8q', native.stdout))
    base = [str(loader), '--mode', 'container', '--root', str(root),
            '-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw', '-v', f'{root}/deny:/deny']
    for option in (None, '--observe-mount-access', '--guard-path-mutations', '--guard-file-mutations'):
        guarded = option == '--guard-file-mutations'
        compile_probe(guarded)
        command = [*base, *([option, 'drwd'] if option else []),
                   *(['--allow-stdio-output'] if guarded else []), '--', './probe', 'guest']
        p = subprocess.run(command, cwd=root, capture_output=True, timeout=20)
        assert p.returncode == 0 and p.stdout==native.stdout, (
            option, p.returncode, p.stdout, p.stderr)
        for name in ('ro', 'rw', 'deny'):
            assert (root / name / 'file').read_bytes()==b'unchanged'
        for name, timestamp in before.items():
            assert (root / name / 'file').stat().st_ctime_ns==timestamp
        print('PASS: ioctl native parity and policy:', option or 'legacy')
    master, slave = os.openpty()
    try:
        p = subprocess.run([*base, '--guard-file-mutations', 'drwd',
                            '--allow-stdio-output', '--', './probe', 'tty'], cwd=root,
                           stdout=slave, stderr=subprocess.PIPE, timeout=20)
        assert p.returncode==0, (p.returncode, p.stderr)
        print('PASS: real PTY queries and mutation/injection rejection')
    finally:
        os.close(master);os.close(slave)
