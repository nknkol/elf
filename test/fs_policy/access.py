#!/usr/bin/env python3
"""Write-access preflight follows path/FD mutation policy without changing files."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo=Path(__file__).resolve().parents[2]
build=lib.BUILD
normal='--normal' in sys.argv
suffix='' if normal else '-guarded'
loader = lib.loader(suffix)
with tempfile.TemporaryDirectory(prefix='access-policy-',dir=build) as tmp:
    root=Path(tmp)
    for name in ('ro','rw','deny','nested'):
        (root/name).mkdir()
        (root/name/'file').write_bytes(b'unchanged')
    (root/'ro/nested').mkdir()
    (root/'ro/to_rw').symlink_to('/rw/file')
    (root/'rw/to_ro').symlink_to('/ro/file')
    before={name:(root/name/'file').stat() for name in ('ro','rw','deny','nested')}
    # Sandbox-development test only: measure the host's existing restrictions
    # on our private symlink, without changing or bypassing the system sandbox.
    native=subprocess.run([sys.executable,'-c',
        'import ctypes,os,sys; c=ctypes.CDLL(None,use_errno=True); c.syscall.restype=ctypes.c_long; '
        'r=c.syscall(439,-100,sys.argv[1].encode(),2,256); '
        'print(-ctypes.get_errno() if r==-1 else r); '
        'fd=os.open(sys.argv[2],os.O_RDONLY); r=c.syscall(439,fd,b"",2,4096); '
        'print(-ctypes.get_errno() if r==-1 else r); os.close(fd); '
        'fd=os.open(sys.argv[2],os.O_RDWR); r=c.syscall(439,fd,b"",2,4096); '
        'print(-ctypes.get_errno() if r==-1 else r); os.close(fd); '
        'r=c.syscall(439,-100,b"",2,4096); print(-ctypes.get_errno() if r==-1 else r)',
        str(root/'ro/to_rw'),str(root/'rw/file')],cwd=root,
        capture_output=True,text=True,timeout=10,check=True)
    link_result,empty_result,inherited_result,cwd_result=map(int,native.stdout.split())
    print('Native W_OK: symlink, empty FD, inherited FD, empty cwd:',
          link_result,empty_result,inherited_result,cwd_result)
    subprocess.run(['clang','-O1','-nostdlib','-static','-ffreestanding','-fno-builtin',
                    '-fno-stack-protector',f'-DNATIVE_LINK_W_OK={link_result}',
                    f'-DNATIVE_EMPTY_W_OK={empty_result}',f'-DNATIVE_INHERITED_W_OK={inherited_result}',
                    f'-DNATIVE_CWD_W_OK={cwd_result}',str(repo/'test/fs_policy/access.c'),'-o',str(root/'probe')],check=True)
    fd=os.open(root/'rw/file',os.O_RDWR)
    try:
        modes=[(None,'none')] if normal else [(None,'none'),('--observe-mount-access','none'),
                            ('--guard-path-mutations','gp'),('--guard-file-mutations','gf')]
        for option,kind in modes:
            p=subprocess.run([str(loader),'--mode','container','--root',str(root),
                              '-v',f'{root}/ro:/ro','-v',f'{root}/rw:/rw',
                              '-v',f'{root}/deny:/deny','-v',f'{root}/nested:/ro/nested',
                              *([option,'drwdw'] if option else []),
                              '--','./probe',kind,str(fd)],cwd=root,pass_fds=(fd,),capture_output=True,timeout=20)
            assert p.returncode==0,(option,p.returncode,p.stdout,p.stderr)
            for name,old in before.items():
                path=root/name/'file';new=path.stat()
                assert path.read_bytes()==b'unchanged'
                assert (old.st_mode,old.st_size,old.st_mtime_ns,old.st_ctime_ns)==(
                    new.st_mode,new.st_size,new.st_mtime_ns,new.st_ctime_ns)
            print('PASS: write-access query paths, links, cwd, empty-path FDs and host state:',option or 'legacy')
    finally:
        os.close(fd)
