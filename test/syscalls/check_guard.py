#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as temp:
    exe=Path(temp)/'guard'
    subprocess.run(['clang','-O2','-pthread','-I'+str(root/'src/payload/include'),str(root/'test/syscalls/guard_test.c'),str(root/'src/payload/arch/aarch64/reentry_guard.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,timeout=30)
