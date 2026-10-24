#!/usr/bin/env python3
"""Build the loader and embedded payload with Clang's freestanding helpers."""
import pathlib
import subprocess
here = pathlib.Path(__file__).resolve().parent
src = here.parent.parent / 'src'
subprocess.run(['clang', '-c', '-ffreestanding', '-fno-builtin', '-fPIC',
                str(here / 'runtime.c'), '-o', str(here / 'runtime.o')], check=True)
# Both loader and payload need compiler-generated memcpy/memset. Keep the
# workaround in this test harness; do not alter production hook behavior.
cmd = ['make', '-B', '-C', str(src), 'ARCH=aarch64', 'CC=clang',
       f'LD=ld.lld {here}/runtime.o', 'OBJCOPY=llvm-objcopy',
       'SHELL_BIN_SRC=/bin/sh',
       f'LDFLAGS=-nostdlib -pie -e z_start -Wl,-Bsymbolic,--no-undefined,--build-id=none {here}/runtime.o']
with (here / 'build.log').open('w') as log:
    subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True)
print('Built:', src / 'elfloader')
