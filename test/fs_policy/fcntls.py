#!/usr/bin/env python3
"""fcntl command admission, native parity and high-bit bookkeeping regression."""
import fcntl
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
loader = lib.loader('-guarded')
with tempfile.TemporaryDirectory(prefix='fcntl-policy-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw', 'deny'):
        (root/name).mkdir()
        (root/name/'file').write_bytes(b'unchanged')
    before = {name:(root/name/'file').stat().st_ctime_ns for name in ('ro','deny')}
    def compile_probe(guarded):
        subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector', *(['-DGUARDED'] if guarded else []),
                        str(repo/'test/fs_policy/fcntls.c'), '-o', str(root/'probe.next')], check=True)
        (root/'probe.next').replace(root/'probe')
    # Hold a real POSIX lock from the host to verify contention, not just
    # successful return codes. Guest F_SETLK/OFD_SETLK must see this same inode.
    with (root/'rw/file').open('r+b') as holder:
        for contended in (False,True):
            if contended:
                fcntl.lockf(holder,fcntl.LOCK_EX|fcntl.LOCK_NB,1)
            compile_probe(False)
            p = subprocess.run([str(root/'probe'), 'native', str(root/'rw/file')],
                               capture_output=True, timeout=10)
            assert p.returncode==0 and len(p.stdout)==80, ('native',p.returncode,p.stdout,p.stderr)
            expected=p.stdout
            results=struct.unpack('10q',expected)
            assert results[1] in (-11,-13) if contended else results[1]==0,results
            assert results[4] in (-11,-13) if contended else results[4]==0,results
            print('Native fcntl results, contended =',contended,results)
            for option in (None,'--observe-mount-access','--guard-path-mutations','--guard-file-mutations'):
                guarded=option=='--guard-file-mutations'
                compile_probe(guarded)
                p=subprocess.run([str(loader),'--mode','container','--root',str(root),
                                  '-v',f'{root}/ro:/ro','-v',f'{root}/rw:/rw','-v',f'{root}/deny:/deny',
                                  *([option,'drwd'] if option else []),
                                  *(['--allow-stdio-output'] if guarded else []),
                                  '--','./probe','guest'],cwd=root,capture_output=True,timeout=20)
                assert p.returncode==0 and p.stdout==expected,(option,p.returncode,p.stdout,p.stderr)
                # Closing another FD for rw/file in this process would release
                # its POSIX lock; inspect through the held FD instead.
                holder.seek(0)
                assert holder.read()==b'unchanged'
                for name in ('ro','deny'):
                    assert (root/name/'file').read_bytes()==b'unchanged'
                for name,stamp in before.items():
                    assert (root/name/'file').stat().st_ctime_ns==stamp
                print('PASS: high-bit FD tracking, native fcntl parity and policy:',option or 'legacy',
                      'contended =',contended)
            if contended:
                fcntl.lockf(holder,fcntl.LOCK_UN,1)
