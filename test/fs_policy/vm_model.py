#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='vm-guard-model-') as tmp:
    exe = Path(tmp) / 'model'
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding',
                    '-fno-builtin', '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'src/payload/logic/vm_write_guard.c'),
                    str(repo / 'test/fs_policy/vm_model.c'), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=20)
