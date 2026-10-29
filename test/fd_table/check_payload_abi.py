#!/usr/bin/env python3
"""PRoot clone-gate ABI: reject old custom payloads before executing a guest."""
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads((build / 'elf-build.json').read_text())['sha256']
original = (repo / 'src/payload/payload.bin').read_bytes()
assert original[:6] == b'\x7fELF\x02\x01'
entry, phoff = struct.unpack_from('<QQ', original, 24)
phsize, phnum = struct.unpack_from('<HH', original, 54)
entry_offset = None
for i in range(phnum):
    kind, _, offset, address, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', original, phoff + i * phsize)
    if kind == 1 and address <= entry and entry + 16 <= address + filesz:
        entry_offset = offset + entry - address
        break
assert entry_offset is not None
assert struct.unpack_from('<I', original, entry_offset + 4)[0] == 0x484F4F4B
assert struct.unpack_from('<I', original, entry_offset + 12)[0] == 5
with tempfile.TemporaryDirectory(prefix='clone-abi-', dir=build) as temp:
    work = Path(temp)
    probe = work / 'probe'
    subprocess.run(['clang', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-O1', '-Wl,-e,_start',
                    str(repo / 'test/syscalls/runtime_probe.c'), '-o', str(probe)], check=True)
    for version in [5, 4, 3, 2, 0]:
        blob = bytearray(original)
        struct.pack_into('<I', blob, entry_offset + 12, version)
        payload = work / f'payload-{version}.bin'
        payload.write_bytes(blob)
        config = work / f'loader-{version}.rc'
        config.write_text(f'PAYLOAD {payload}\n')
        p = subprocess.run([str(loader), '-c', str(config), '--mode', 'compat', '--', str(probe), 'c'],
                           capture_output=True, text=True, timeout=15)
        if version == 5:
            assert p.returncode == 0 and 'STATUS=10752\n' in p.stdout, (p.stdout, p.stderr)
        else:
            assert p.returncode != 0 and 'payload ABI mismatch' in p.stdout + p.stderr, (p.stdout, p.stderr)
            assert 'CLONE=' not in p.stdout
        print('PASS: custom payload ABI', version)
