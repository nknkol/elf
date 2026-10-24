#!/usr/bin/env python3
"""Metadata mutation outcomes compared with native private-fixture controls."""
import hashlib,json,re,stat,subprocess,tempfile
from pathlib import Path
base=Path(__file__).resolve().parents[1]
build=base/'svc/build';loader=build/'elfloader-proot'
assert hashlib.sha256(loader.read_bytes()).hexdigest()==json.loads((build/'elf-build.json').read_text())['sha256']
results=[]
with tempfile.TemporaryDirectory(prefix='modify-',dir=build) as temp:
    work=Path(temp);probe=work/'probe'
    subprocess.run(['clang','-nostdlib','-static','-ffreestanding','-fno-builtin','-fno-stack-protector','-O1','-Wl,-e,_start',str(base/'port-tests/svc_modify_probe.c'),'-o',str(probe)],check=True)
    cases=[('chmod','c','file'),('fchmod','C','file'),('chown','o','file'),('lchown','l','link'),('fchown','O','file'),('utimens','u','file'),('lutimens','n','link'),('fd-utimens','U','file'),('truncate','t','file'),('ftruncate','T','file'),('statfs','s','file'),('fstatfs','S','file'),('fifo','m','fifo'),('fifo-existing-link','m','link'),('bad-fd','b','file'),('bad-flags','f','file'),('chmod-missing','c','missing'),('chown-missing','o','missing'),('utimens-missing','u','missing'),('truncate-link','t','link')]
    for name,op,target in cases:
        outcomes=[]
        for backend in ['native','loader']:
            root=work/(name+'-'+backend);bound=root/'bound';bound.mkdir(parents=True)
            (root/'mnt').mkdir();(bound/'file').write_text('abcdef');(bound/'link').symlink_to('file')
            (bound/'file').chmod(0o644)
            # Fixed baseline timestamps allow exact mutation assertions.
            import os
            os.utime(bound/'file',(1000000,1000000));os.utime(bound/'link',(1000000,1000000),follow_symlinks=False)
            if backend=='native': cmd=[str(probe),op,str(bound/target)]
            else:
                (root/'probe').write_bytes(probe.read_bytes());(root/'probe').chmod(0o755)
                cmd=[str(loader),'--mode','compat','--root',str(root),'-v',f'{bound}:/mnt','--','./probe',op,'/mnt/'+target]
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=15)
            assert p.returncode==0,(name,backend,p.stdout,p.stderr)
            ret=int(re.search(r'RET=(-?\d+)',p.stdout)[1])
            f=(bound/'file').stat();l=(bound/'link').lstat()
            outcome=dict(ret=ret,mode=stat.S_IMODE(f.st_mode),size=f.st_size,mtime=f.st_mtime_ns,link_mtime=l.st_mtime_ns,fifo=(bound/'fifo').exists())
            if op in ('t','T') and ret==0:
                outcome['mtime']=('updated' if f.st_mtime_ns!=1000000000000000 else 'unchanged')
            outcomes.append(outcome)
            if ret==0:
                # This host may mask reported mode bits; compare native below.
                if op in ('t','T'):assert outcome['size']==2
                if op in ('u','U'):assert outcome['mtime']==1234567000000000
                if op=='n':assert outcome['link_mtime']==1234567000000000 and outcome['mtime']==1000000000000000
                if op=='m':assert stat.S_ISFIFO((bound/'fifo').stat().st_mode)
        assert outcomes[0]==outcomes[1],(name,outcomes)
        results.append(dict(name=name,native=outcomes[0],loader=outcomes[1]))
        (build/'modify-results.json').write_text(json.dumps(results,indent=2))
        print('PASS:',name)
print(len(results),'metadata mutation checks passed')
