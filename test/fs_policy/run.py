#!/usr/bin/env python3
"""Standalone policy and PRoot mount-selection checks, not runtime enforcement."""
import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='fs-policy-') as tmp:
    obj = Path(tmp) / 'policy.o'
    exe = Path(tmp) / 'check'
    flags = ['clang', '-std=c11', '-D_GNU_SOURCE', '-Wall', '-Wextra', '-Werror',
             '-O2', '-I' + str(repo / 'src/payload/include'),
             '-I' + str(repo / 'vendor/proot/src')]
    subprocess.run([*flags, '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                    '-c', str(repo / 'src/payload/logic/fs_policy.c'), '-o', str(obj)], check=True)
    undefined = subprocess.check_output(['llvm-nm', '--undefined-only', str(obj)], text=True)
    assert not undefined.strip(), undefined
    subprocess.run([*flags, str(repo / 'test/fs_policy/check.c'), str(obj),
                    str(repo / 'vendor/proot/src/path/binding_core.c'),
                    str(repo / 'vendor/proot/src/path/path_helpers.c'),
                    '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=20)
