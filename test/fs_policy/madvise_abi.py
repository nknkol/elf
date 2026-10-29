#!/usr/bin/env python3
"""Reject high-bit MADV_REMOVE after admission loss; verify actual file bytes."""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
repo=Path(__file__).resolve().parents[2]
build=repo/'vendor/proot/svc/build'
loader=build/'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest()==json.loads(
    (build/'elf-build-fd-experiment.json').read_text())['sha256']
page=os.sysconf('SC_PAGE_SIZE')
with tempfile.TemporaryDirectory(prefix='madvise-abi-',dir=build) as tmp:
    root=Path(tmp)
    (root/'rw').mkdir()
    probe=root/'probe'
    target=root/'rw/file'
    subprocess.run(['clang','-O1','-nostdlib','-static','-ffreestanding','-fno-builtin',
                    '-fno-stack-protector',f'-DPAGE_SIZE={page}',
                    str(repo/'test/fs_policy/madvise_abi.c'),'-o',str(probe)],check=True)
    for option in ('native',None,'--observe-mount-access','--guard-path-mutations','--guard-file-mutations'):
        for variant in ('low','high','sign'):
            target.write_bytes(b'Z'*page)
            before=target.stat()
            guarded=option=='--guard-file-mutations'
            if option=='native':
                command=[str(probe),str(target),'native',variant]
            else:
                command=[str(loader),'--mode','container','--root',str(root),
                         '-v',f'{root}/rw:/rw',*([option,'dw'] if option else []),
                         '--','./probe','/rw/file','guarded' if guarded else 'native',variant]
            p=subprocess.run(command,cwd=root,capture_output=True,timeout=20)
            actual=target.read_bytes()
            assert p.returncode==0,(option,variant,p.returncode,'file_zeroed',actual==bytes(page),p.stderr)
            assert actual==(b'Z'*page if guarded else bytes(page)),(option,variant)
            if guarded:
                after=target.stat()
                assert (before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(
                    after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            print('PASS: madvise ABI, live shared mapping and host bytes:',option or 'legacy',variant)
