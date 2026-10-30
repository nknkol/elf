#!/usr/bin/env python3
"""Build the loader (with its embedded payload) into build/.

build/elfloader, or build/elfloader-guarded with --guarded, plus a manifest
(build/elfloader[-guarded].json) recording its hash: tests refuse a binary
that is not the last one built. A failed build leaves no manifest."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from elf_abi import LOADER_FIXED_BASE

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--guarded', action='store_true', help='include the guarded FD runtime')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
build = repo / 'build'
build.mkdir(exist_ok=True)
name = 'elfloader-guarded' if args.guarded else 'elfloader'
(build / f'{name}.json').unlink(missing_ok=True)
# Dependency files hold absolute paths; drop them after repository moves.
shutil.rmtree(repo / 'src/payload/proot-build', ignore_errors=True)
with (build / f'{name}.log').open('w') as log:
    # Static and non-PIE at a fixed address: no host dynamic linker in guest
    # processes, and the seccomp backstop allows the loader's own syscalls
    # by address across every exec.
    subprocess.run(['make', '-B', '-C', str(repo / 'src'), 'CC=clang', 'LD=ld.lld',
                    'OBJCOPY=llvm-objcopy', f'GUARDED={int(args.guarded)}',
                    f'LDFLAGS=-nostdlib -static -no-pie -Wl,--image-base={LOADER_FIXED_BASE:#x} '
                    '-e z_start -Wl,--no-undefined,--build-id=none'],
                   stdout=log, stderr=subprocess.STDOUT, check=True)
binary = build / name
pending = build / f'{name}.next'
shutil.copy2(repo / 'src/elfloader', pending)
pending.replace(binary)
manifest = {'guarded': args.guarded, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
if args.guarded:
    # First guest program of tools/agent_sandbox/launch.py. Static-pie keeps
    # it near the loader's stubs; it carries no relocations.
    helper = build / 'elf-exec-helper'
    subprocess.run(['clang', '-O1', '-static-pie', '-fPIE', '-nostdlib', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', '-I', str(repo / 'src/payload/include'),
                    str(repo / 'tools/agent_sandbox/exec_helper.c'), '-o', str(helper)], check=True)
    manifest['exec_helper_sha256'] = hashlib.sha256(helper.read_bytes()).hexdigest()
(build / f'{name}.json').write_text(json.dumps(manifest, indent=2))
print('Built', binary)
