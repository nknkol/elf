#!/usr/bin/env python3
import hashlib,json,subprocess,tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
here = Path(__file__).resolve().parent;build=lib.BUILD;loader = lib.loader()
with tempfile.TemporaryDirectory(prefix='auxv-',dir=build) as temp:
    root=Path(temp);probe=root/'probe'
    subprocess.run([*lib.PROBE,str(here/'svc_auxv_probe.c'),'-o',str(probe)],check=True)
    results=[]
    for mode in ['compat','container']:
        for stage,expected in [('check','./probe'),('x','/probe')]:
            p=subprocess.run([str(loader),'--mode',mode,'--root',str(root),'--','./probe',stage],capture_output=True,text=True,timeout=15)
            results.append(dict(mode=mode,stage=stage,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr))
            (build/'auxv-results.json').write_text(json.dumps(results,indent=2))
            assert p.returncode==0 and 'AUXV_OK\n' in p.stdout and f'EXECFN={expected}\n' in p.stdout,results[-1]
            print('PASS: stack snapshot, size/truncation/EFAULT/flags/identity',mode,stage)
