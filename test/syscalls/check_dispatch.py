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
assert number('__NR_unshare') == 97
assert number('__NR_kcmp') == 272
inventory = subprocess.check_output(['clang', '-E', '-P', '-I'+str(arch), '-'],
    input='#include "syscall_nums.h"\n#define SLOW_SYSCALL(n) selected(n)\n#include "slow_syscalls.inc"\n', text=True)
selected = {int(n) for n in re.findall(r'selected\((\d+)\)', inventory)}
for name in ('exit', 'exit_group', 'clone', 'rt_sigreturn', 'futex', 'getpid'):
    assert number('__NR_'+name) not in selected, name
for name in ('openat', 'read', 'write', 'fchmodat', 'fchmodat2', 'io_uring_enter', 'openat2', 'inotify_add_watch', 'close_range',
             'unshare', 'mount', 'umount2', 'chroot', 'setns', 'pivot_root', 'kcmp'):
    assert number('__NR_'+name) in selected, name
with tempfile.TemporaryDirectory() as temp:
    obj = Path(temp)/'entry.o'
    exe = Path(temp)/'probe'
    subprocess.run(['clang', '-c', '-D_start=hook_entry', '-I'+str(root/'src/payload/include'), '-I'+str(arch), str(arch/'entry.S'), '-o', str(obj)], check=True)
    subprocess.run(['clang', '-nostdlib', '-static', '-Wl,-e,_start', '-I'+str(arch), str(obj), str(root/'test/syscalls/dispatch_probe.S'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=10)
print(f'PASS: ABI constants, {len(selected)} selected slow calls, fast getpid/unknown and exit routing')
