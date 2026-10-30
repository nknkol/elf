#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as temp:
    exe=Path(temp)/'guard'
    subprocess.run(['clang','-O2','-pthread','-I'+str(root/'src/payload/include'),str(root/'test/syscalls/guard_test.c'),str(root/'src/payload/arch/aarch64/reentry_guard.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe),"--nested-init"],check=True,timeout=30)
    subprocess.run([str(exe)],check=True,timeout=30)
    private=Path(temp)/'guard-private'
    subprocess.run(['clang','-O2','-DGUARDED','-I'+str(root/'src/payload/include'),
                    str(root/'test/syscalls/guard_private_test.c'),
                    str(root/'src/payload/arch/aarch64/reentry_guard.c'),'-o',str(private)],check=True)
    subprocess.run([str(private)],check=True,timeout=30)
