#!/usr/bin/env python3
"""Build experimental path bridge; force rebuild when switching backend."""
from pathlib import Path
import subprocess
import shutil
import hashlib,json
here=Path(__file__).resolve().parent
elf=here.parents[2]
build=here/'build'
build.mkdir(exist_ok=True)
# Invalidate success marker before any build step; failed builds cannot be tested.
(build/'elf-build.json').unlink(missing_ok=True)
# Dependency files contain source paths; discard them after repository moves.
shutil.rmtree(elf/'src/payload/proot-build', ignore_errors=True)
# Loader still needs only memcpy/memset. Payload gets the complete core runtime.
subprocess.run(['clang','-c','-ffreestanding','-fno-builtin','-fPIC',
                str(elf/'test/svc_probe/runtime.c'),'-o',str(build/'loader_memory.o')],check=True)
with (build/'elf-build.log').open('w') as log:
    subprocess.run(['make','-B','-C',str(elf/'src'),'ARCH=aarch64','CC=clang',
                    'LD=ld.lld','OBJCOPY=llvm-objcopy','SHELL_BIN_SRC=/bin/sh',
                    'PROOT_PATH=1',
                    f'LDFLAGS=-nostdlib -pie -e z_start -Wl,-Bsymbolic,--no-undefined,--build-id=none {build}/loader_memory.o'],
                   stdout=log,stderr=subprocess.STDOUT,check=True)
snapshot=build/'elfloader-proot'
pending=build/'elfloader-proot.next'
pending.unlink(missing_ok=True)
shutil.copy2(elf/'src/elfloader',pending)
pending.replace(snapshot)
(build/'elf-build.json').write_text(json.dumps({'backend':'proot-path','sha256':hashlib.sha256(snapshot.read_bytes()).hexdigest()},indent=2))
print('Built experimental PRoot path backend:',snapshot)
