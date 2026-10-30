#!/usr/bin/env python3
"""Malformed or conflicting ELF layouts are refused before anything is mapped.

A fixed image placed over the loader or the payload used to replace them
(MAP_FIXED) and crash; segments whose file size exceeds their memory size
or that reach past the end of the file are rejected too. Each bad program
exits with status 1 from the loader, never a signal, and the well-formed
original still runs. Both builds."""
import struct
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
    print('SKIP: rootfs unavailable:', alpine)
    raise SystemExit(0)
release = (alpine / 'etc/alpine-release').read_text().strip()
CC = [*lib.PROBE, '-Wl,--no-rosegment',
      str(repo / 'test/fs_policy/code_only_probe.c')]


def patch_load(path, out, change):
    data = bytearray(path.read_bytes())
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phnum, = struct.unpack_from('<H', data, 0x38)
    loads = [phoff + i * 56 for i in range(phnum) if struct.unpack_from('<I', data, phoff + i * 56)[0] == 1]
    change(data, loads[-1])
    out.write_bytes(data)
    out.chmod(0o755)


with tempfile.TemporaryDirectory(prefix='elf-layout-', dir=build) as tmp:
    work = Path(tmp)
    good = work / 'good'
    subprocess.run(CC + ['-o', str(good)], check=True)
    for name, base in (('over-loader', '0x3f00000000'), ('over-payload', '0x3f80000000')):
        subprocess.run(CC + [f'-Wl,--image-base={base}', '-o', str(work / name)], check=True)
    # p_filesz at +32, p_memsz at +40, p_offset at +8 of a program header.
    patch_load(good, work / 'filesz', lambda d, o: struct.pack_into(
        '<Q', d, o + 32, struct.unpack_from('<Q', d, o + 40)[0] + 0x10000))
    patch_load(good, work / 'offset', lambda d, o: struct.pack_into('<Q', d, o + 8, len(d) - 8))
    script = '; '.join(f'/work/{n} >/dev/null 2>&1; echo {n}=$?' for n in
                       ('over-loader', 'over-payload', 'filesz', 'offset'))
    for suffix in ('', '-guarded'):
        loader = build / f'elfloader{suffix}'
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                            '-v', f'{work}:/work', '--', './bin/busybox', 'sh', '-c',
                            f'/work/good; {script}'],
                           cwd=alpine, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, (suffix, p.stdout, p.stderr[-800:])
        assert p.stdout.split() == ['literal=patched', f'open={release}', 'over-loader=1',
                                    'over-payload=1', 'filesz=1', 'offset=1'], (suffix, p.stdout)
        print('PASS: malformed and conflicting ELF layouts are refused:', loader.name)
