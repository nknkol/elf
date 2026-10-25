#!/usr/bin/env python3
"""Exercise the real clone notification assembly and C observers with kernel clone."""
import re
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='clone-notify-') as temp:
    exe = Path(temp) / 'probe'
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-Wl,-no-pie',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/clone_notify_test.c'),
                    str(repo / 'test/fd_table/clone_notify_probe.S'),
                    str(repo / 'src/payload/arch/aarch64/clone_entry.S'),
                    str(repo / 'src/payload/logic/clone_notify.c'), '-o', str(exe)], check=True)
    symbols = subprocess.check_output(['llvm-nm', str(exe)], text=True)
    addresses = {name: int(value, 16) for value, name in
                 re.findall(r'^([0-9a-f]+) [a-zA-Z] (\w+)$', symbols, re.M)}
    assert addresses['test_data'] - addresses['test_stub'] == 160
    assert addresses['test_resume'] - addresses['test_stub'] == 100
    subprocess.run([str(exe), "--nested-init"], check=True, timeout=30)
    subprocess.run([str(exe)], check=True, timeout=30)
