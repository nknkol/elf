#!/usr/bin/env python3
"""Build experimental path bridge; force rebuild when switching backend."""
from pathlib import Path
import subprocess
import shutil
import hashlib,json,argparse
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument("--fd-experiment",action="store_true")
args=parser.parse_args()
suffix="-fd-experiment" if args.fd_experiment else ""
here=Path(__file__).resolve().parent
elf=here.parents[2]
build=here/'build'
build.mkdir(exist_ok=True)
# Invalidate success marker before any build step; failed builds cannot be tested.
(build/('elf-build'+suffix+'.json')).unlink(missing_ok=True)
# Dependency files contain source paths; discard them after repository moves.
shutil.rmtree(elf/'src/payload/proot-build', ignore_errors=True)
# Loader still needs only memcpy/memset. Payload gets the complete core runtime.
subprocess.run(['clang','-c','-ffreestanding','-fno-builtin','-fPIC',
                str(elf/'test/svc_probe/runtime.c'),'-o',str(build/'loader_memory.o')],check=True)
with (build/('elf-build'+suffix+'.log')).open('w') as log:
    subprocess.run(['make','-B','-C',str(elf/'src'),'ARCH=aarch64','CC=clang',
                    'LD=ld.lld','OBJCOPY=llvm-objcopy','SHELL_BIN_SRC=/bin/sh',
                    'PROOT_PATH=1', f'FD_EXPERIMENT={int(args.fd_experiment)}',
                    f'LDFLAGS=-nostdlib -pie -e z_start -Wl,-Bsymbolic,--no-undefined,--build-id=none {build}/loader_memory.o'],
                   stdout=log,stderr=subprocess.STDOUT,check=True)
snapshot=build/('elfloader-proot'+suffix)
pending=build/('elfloader-proot'+suffix+'.next')
pending.unlink(missing_ok=True)
shutil.copy2(elf/'src/elfloader',pending)
pending.replace(snapshot)
manifest={'backend':'proot-path','fd_experiment':args.fd_experiment,'sha256':hashlib.sha256(snapshot.read_bytes()).hexdigest()}
if args.fd_experiment:
    # First guest program of tools/agent_sandbox/launch.py. Static-pie keeps
    # it near the loader's SVC stubs; it carries no relocations.
    helper=build/'elf-exec-helper'
    subprocess.run(['clang','-O1','-static-pie','-fPIE','-nostdlib','-ffreestanding','-fno-builtin',
                    '-fno-stack-protector',str(elf/'tools/agent_sandbox/exec_helper.c'),
                    '-o',str(helper)],check=True)
    manifest['exec_helper_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()
(build/('elf-build'+suffix+'.json')).write_text(json.dumps(manifest,indent=2))
print('Built experimental PRoot path backend:',snapshot)
