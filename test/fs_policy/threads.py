#!/usr/bin/env python3
"""Threads in the FD experiment: shared metadata under concurrent FD churn."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
loader = lib.loader('-guarded')

GUEST = r'''
import errno, json, mmap, os, socket, subprocess, sys, threading
rw, ro = sys.argv[1], sys.argv[2]
errors, counts, children = [], [0] * 8, []
def worker(i):
    try:
        for _ in range(150):
            path = f"{rw}/t{i}"
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(fd, b"x" * 64)
            os.lseek(fd, 0, 0)
            assert os.read(fd, 64) == b"x" * 64
            with mmap.mmap(fd, 64) as shared:
                shared[0:1] = b"y"
            copy = os.dup(fd)
            os.close(fd)
            os.write(copy, b"z")
            os.close(copy)
            try:
                os.close(os.open(f"{ro}/file", os.O_WRONLY))
                errors.append("ro-open")
            except OSError as exc:
                assert exc.errno == errno.EROFS, exc
            reader = os.open(f"{ro}/file", os.O_RDONLY)
            try:
                os.write(reader, b"!")
                errors.append("ro-write")
            except OSError as exc:
                assert exc.errno == errno.EROFS, exc
            os.close(reader)
            left, right = socket.socketpair()
            left.send(b"q"); assert right.recv(1) == b"q"
            os.write(left.fileno(), b"w"); assert right.recv(1) == b"w"
            left.close(); right.close()
            counts[i] += 1
    except Exception as exc:
        errors.append(repr(exc))
def spawner():
    try:
        for _ in range(5):
            out = subprocess.run([sys.executable, "-B", "-c", "print('child-ok')"],
                                 capture_output=True, text=True)
            children.append(out.stdout.strip())
    except Exception as exc:
        errors.append("spawn " + repr(exc))
threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
threads.append(threading.Thread(target=spawner))
for t in threads: t.start()
for t in threads: t.join()
print(json.dumps({"errors": errors, "counts": counts, "children": children}))
'''

with tempfile.TemporaryDirectory(prefix='threads-', dir=build) as tmp:
    root = Path(tmp)
    (root / 'rw').mkdir()
    (root / 'ro').mkdir()
    (root / 'ro/file').write_bytes(b'readonly')
    before = (root / 'ro/file').stat()
    python = str(Path(sys.executable).resolve())
    # Root "/" readonly keeps the interpreter and its libraries reachable.
    p = subprocess.run([str(loader), '--mode', 'container', '--root', '/',
                        '-v', f'{root}/rw:/elf-rw', '-v', f'{root}/ro:/elf-ro',
                        '--guard-file-mutations', 'rwr', '--allow-stdio-output',
                        '--allow-pipe-output', '--allow-local-output', '--revalidate-file-fds',
                        '--', python.lstrip('/'), '-B', '-c', GUEST, '/elf-rw', '/elf-ro'],
                       cwd='/', capture_output=True, text=True, timeout=300)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr[-3000:])
    result = json.loads(p.stdout.strip().splitlines()[-1])
    assert result['errors'] == [], result['errors'][:5]
    assert result['counts'] == [150] * 8, result
    assert result['children'] == ['child-ok'] * 5, result
    after = (root / 'ro/file').stat()
    assert (root / 'ro/file').read_bytes() == b'readonly'
    assert (before.st_mtime_ns, before.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns)
    for index in range(8):
        assert (root / f'rw/t{index}').read_bytes() == b'y' + b'x' * 63 + b'z'
    print('PASS: 8 threads of FD churn, mappings, sockets, readonly denial and concurrent fork/exec')
