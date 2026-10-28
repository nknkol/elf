#!/usr/bin/env python3
from pathlib import Path
import os
import hashlib
import json
import subprocess
import tempfile
root = Path(__file__).resolve().parents[2]
build = root/'vendor/proot/svc/build'
loader = build/'elfloader-proot'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads((build/'elf-build.json').read_text())['sha256']
results = []
with tempfile.TemporaryDirectory(prefix='dispatch-runtime-', dir=build) as temp:
    probe = Path(temp)/'probe'
    subprocess.run(['clang','-nostdlib','-static','-ffreestanding','-fno-builtin','-fno-stack-protector','-O1','-Wl,-e,_start',str(root/'test/syscalls/runtime_probe.c'),'-o',str(probe)],check=True)
    for mode, expected in [('s', ['ACTION=0', 'SIGNAL=10']), ('c', ['CLONE=0', 'WAIT=0', 'STATUS=10752']), ('b', [])]:
        for backend in (['native','loader'] if mode != 'b' else ['loader']):
            cmd = [str(probe), mode]
            if backend == 'loader': cmd = [str(loader), '--mode', 'compat', '--'] + cmd
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            results.append(dict(backend=backend,mode=mode,returncode=p.returncode,output=p.stdout,stderr=p.stderr))
            (build/'dispatch-runtime.json').write_text(json.dumps(results,indent=2))
            assert p.returncode == 0, results[-1]
            for item in expected: assert item+'\n' in p.stdout, results[-1]
            if mode == 'b': assert p.stdout.count('RET=-38\n') == 7 and 'NR=452\nRET=-38\n' in p.stdout, results[-1]
            print('PASS:',backend,mode)

with tempfile.TemporaryDirectory(prefix='range-runtime-', dir=build) as temp:
    probe = Path(temp) / 'range'
    subprocess.run(['clang', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-O1', '-DFD_TRACK=0',
                    '-I' + str(root / 'src/payload/include'),
                    str(root / 'test/fd_runtime/range.c'), '-o', str(probe)], check=True)
    inherited = os.memfd_create('range-inherited', flags=0)
    try:
        p = subprocess.run([str(loader), '--mode', 'compat', '--', str(probe), str(inherited)],
                           pass_fds=(inherited,), capture_output=True, text=True, timeout=15)
        assert p.returncode == 0 and 'PASS:' in p.stdout, (p.returncode, p.stdout, p.stderr)
        print(p.stdout, end='')
    finally:
        os.close(inherited)
