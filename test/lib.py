"""Shared test helpers: build outputs, the loaders, probes and guest runs.

Tests import it after `sys.path.insert(0, <repo>/test)`:
    import lib
    for suffix, loader in lib.loaders(): ...
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BUILD = REPO / 'build'
ALPINE = BUILD / 'alpine-test-root'
UBUNTU = BUILD / 'ubuntu-test-root'
SUFFIXES = ('', '-guarded')
sys.path.insert(0, str(REPO / 'tools'))
import elf_abi  # noqa: E402  (tools/elf_abi.py)
ABI = elf_abi


def loader(suffix=''):
    """build/elfloader<suffix>, checked against the manifest of its build."""
    path = BUILD / f'elfloader{suffix}'
    manifest = json.loads((BUILD / f'elfloader{suffix}.json').read_text())
    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest['sha256'], \
        f'{path.name} is not the binary of its last build'
    return path


def loaders():
    """(suffix, loader) for the plain and the guarded build."""
    return [(suffix, loader(suffix)) for suffix in SUFFIXES]


def require(path, what='rootfs'):
    """Exit with SKIP when a prepared tree (a test rootfs) is missing."""
    if not Path(path).exists():
        print(f'SKIP: {what} unavailable:', path)
        raise SystemExit(0)
    return Path(path)


PROBE = ['clang', '-O1', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
         '-fno-stack-protector', '-Wl,-e,_start']


def build_probe(source, output, *flags):
    """A freestanding static probe (entry _start, raw syscalls)."""
    subprocess.run([*PROBE, *flags, str(source), '-o', str(output)], check=True)
    return Path(output)


def guest(loader, command, root=ALPINE, volumes=(), options=(), mode='container', cwd=None,
          timeout=60, **kwargs):
    """Runs command under the loader with root and host:guest volumes."""
    argv = [str(loader), '--mode', mode, '--root', str(root)]
    for host, guest_path in volumes:
        argv += ['-v', f'{host}:{guest_path}']
    argv += [*options, '--', *command]
    kwargs.setdefault('capture_output', True)
    kwargs.setdefault('text', True)
    return subprocess.run(argv, cwd=cwd or root, timeout=timeout, **kwargs)
