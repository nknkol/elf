#!/usr/bin/env python3
"""Real loader/payload/exec observation transport; no permission enforcement."""
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']
with tempfile.TemporaryDirectory(prefix='policy-transport-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw'):
        (root / name).mkdir()
    base = [str(loader), '--mode', 'container', '--root', str(root),
            '-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw']
    def run(options):
        return subprocess.run([*base, *options, '--', './probe'], cwd=root,
                              capture_output=True, text=True, timeout=20)
    for enabled in (True, False):
        subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector',
                        *([] if enabled else ['-DNO_POLICY']),
                        '-I' + str(repo / 'src/payload/include'),
                        str(repo / 'test/fs_policy/transport.c'), '-o', str(root / 'probe.next')], check=True)
        (root / 'probe.next').replace(root / 'probe')
        p = run(['--observe-mount-access', 'drw'] if enabled else [])
        assert p.returncode == 0 and 'PASS: policy observation' in p.stdout, (p.returncode, p.stdout, p.stderr)
        print('PASS: real exec transport, observation enabled =', enabled)
    for options in (['--observe-mount-access', v] for v in ('', 'dr', 'drww', 'drx', 'w'*10)):
        p = run(options)
        assert p.returncode != 0 and 'mount access observation' in p.stdout+p.stderr, (options, p.stdout, p.stderr)
    p = run(['--observe-mount-access', 'drw', '--observe-mount-access', 'drw'])
    assert p.returncode != 0 and 'duplicate mount access observation' in p.stdout+p.stderr
    for guard in ('--guard-path-mutations', '--guard-file-mutations'):
        p = run(['--observe-mount-access', 'drw', guard, 'drw'])
        assert p.returncode != 0 and 'duplicate mount access observation' in p.stdout+p.stderr
    print('PASS: reject empty, malformed, oversized, mismatched and duplicate policies')
    # Verify the actual experimental payload layout has its own ABI version,
    # and old custom payload headers are rejected before guest startup.
    blob = (repo / 'src/payload/payload.bin').read_bytes()
    entry, phoff = struct.unpack_from('<QQ', blob, 24)
    phsize, phnum = struct.unpack_from('<HH', blob, 54)
    offset = None
    for i in range(phnum):
        kind, _, off, addr, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', blob, phoff+i*phsize)
        if kind == 1 and addr <= entry and entry+16 <= addr+size:
            offset = off+entry-addr
            break
    assert offset is not None and struct.unpack_from('<I', blob, offset+12)[0] == 7
    for version in (6, 5, 4, 3, 2):
        old = bytearray(blob)
        struct.pack_into('<I', old, offset+12, version)
        payload = root / f'old-{version}.bin'
        payload.write_bytes(old)
        config = root / 'payload.rc'
        config.write_text(f'PAYLOAD {payload}\n')
        p = subprocess.run([str(loader), '-c', str(config), '--mode', 'compat',
                            '--', str(root / 'probe')], capture_output=True, text=True, timeout=20)
        assert p.returncode != 0 and 'payload ABI mismatch' in p.stdout+p.stderr, (p.stdout, p.stderr)
    print('PASS: experimental ABI 7 rejects older payload layouts')
