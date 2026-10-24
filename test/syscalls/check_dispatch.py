#!/usr/bin/env python3
"""Check target ABI constants and real assembly dispatch routing."""
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
arch = root/'src/payload/arch/aarch64'
macros = subprocess.check_output(['clang', '-dM', '-E', '-I'+str(arch), '-'],
                                input='#include "syscall_nums.h"\n', text=True)
values = dict(re.findall(r'^#define (\w+) (.+)$', macros, re.M))
def number(name):
    value = values[name]
    return number(value) if value in values else int(value, 0)
for key in values:
    if key.startswith('SYS_'):
        assert number(key) == number('__NR_'+key[4:]), key
assert number('SYS_rt_sigaction') == 134
with tempfile.TemporaryDirectory() as temp:
    obj = Path(temp)/'entry.o'
    exe = Path(temp)/'probe'
    subprocess.run(['clang', '-c', '-D_start=hook_entry', '-I'+str(arch), str(arch/'entry.S'), '-o', str(obj)], check=True)
    subprocess.run(['clang', '-nostdlib', '-static', '-Wl,-e,_start', str(obj), str(root/'test/syscalls/dispatch_probe.S'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=10)
print('PASS: ABI constants and 1022 syscall numbers reach the real assembly slow path')
