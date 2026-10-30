#!/usr/bin/env python3
"""Payload ABI: a payload of another version is refused before the guest runs."""
import hashlib
import json
import re
import struct
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
loader = lib.loader()
ABI = int(re.search(r'#define PAYLOAD_ABI_VERSION (\d+)', (repo / 'src/payload/include/elf_abi.h').read_text()).group(1))
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
assert struct.unpack_from('<I', original, entry_offset + 12)[0] == ABI
with tempfile.TemporaryDirectory(prefix='clone-abi-', dir=build) as temp:
    work = Path(temp)
    probe = work / 'probe'
    subprocess.run(['clang', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-O1', '-Wl,-e,_start',
                    str(repo / 'test/syscalls/runtime_probe.c'), '-o', str(probe)], check=True)
    for version in [ABI, ABI - 1, 5, 2, 0]:
        blob = bytearray(original)
        struct.pack_into('<I', blob, entry_offset + 12, version)
        payload = work / f'payload-{version}.bin'
        payload.write_bytes(blob)
        p = subprocess.run([str(loader), '--payload', str(payload), '--mode', 'compat', '--', str(probe), 'c'],
                           capture_output=True, text=True, timeout=15)
        if version == ABI:
            assert p.returncode == 0 and 'STATUS=10752\n' in p.stdout, (p.stdout, p.stderr)
        else:
            assert p.returncode != 0 and 'payload ABI mismatch' in p.stdout + p.stderr, (p.stdout, p.stderr)
            assert 'CLONE=' not in p.stdout
        print('PASS: custom payload ABI', version)
