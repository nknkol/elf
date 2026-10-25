#!/usr/bin/env python3
"""Standalone FD metadata core plus native kernel lifecycle comparisons.
This does not test interception: the core is not yet wired into the payload.
"""
import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='fd-table-') as temp:
    obj = Path(temp) / 'fd_table.o'
    exe = Path(temp) / 'check'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                    '-I' + str(repo / 'src/payload/include'), '-c',
                    str(repo / 'src/payload/logic/fd_table.c'), '-o', str(obj)], check=True)
    undefined = subprocess.check_output(['llvm-nm', '--undefined-only', str(obj)], text=True)
    assert not undefined.strip(), undefined
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/check.c'), str(obj), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=20)
