#!/usr/bin/env python3
import hashlib,json,subprocess,tempfile
from pathlib import Path
base=Path(__file__).resolve().parents[1];build=base/'svc/build';loader=build/'elfloader-proot'
assert hashlib.sha256(loader.read_bytes()).hexdigest()==json.loads((build/'elf-build.json').read_text())['sha256']
with tempfile.TemporaryDirectory(prefix='auxv-',dir=build) as temp:
    root=Path(temp);probe=root/'probe'
    subprocess.run(['clang','-nostdlib','-static','-ffreestanding','-fno-builtin','-fno-stack-protector','-O1','-Wl,-e,_start',str(base/'port-tests/svc_auxv_probe.c'),'-o',str(probe)],check=True)
    results=[]
    for mode in ['compat','container']:
        for stage,expected in [('check','./probe'),('x','/probe')]:
            p=subprocess.run([str(loader),'--mode',mode,'--root',str(root),'--','./probe',stage],capture_output=True,text=True,timeout=15)
            results.append(dict(mode=mode,stage=stage,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr))
            (build/'auxv-results.json').write_text(json.dumps(results,indent=2))
            assert p.returncode==0 and 'AUXV_OK\n' in p.stdout and f'EXECFN={expected}\n' in p.stdout,results[-1]
            print('PASS: stack snapshot, size/truncation/EFAULT/flags/identity',mode,stage)
