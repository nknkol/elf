#!/usr/bin/env python3
"""Signed-loader exec continuity, using ordinary guest SVC calls."""
from pathlib import Path
import hashlib,json,subprocess,tempfile
base=Path(__file__).resolve().parent.parent
build=base/'svc/build'; elf=build/'elfloader-proot'
assert hashlib.sha256(elf.read_bytes()).hexdigest()==json.loads((build/'elf-build.json').read_text())['sha256']
results=[]
with tempfile.TemporaryDirectory(prefix='exec-',dir=build) as tmp:
    root=Path(tmp)/'root';bound=Path(tmp)/'bound'
    for p in (root/'real',root/'mnt',bound):p.mkdir(parents=True,exist_ok=True)
    (root/'real/file').write_text('ROOT\n');(bound/'file').write_text('BOUND\n')
    subprocess.run(['clang','-nostdlib','-static','-ffreestanding','-fno-builtin','-fno-stack-protector','-O1','-Wl,-e,_start',str(base/'port-tests/svc_exec_probe.c'),'-o',str(root/'probe')],check=True)
    (bound/'child').write_bytes((root/'probe').read_bytes());(bound/'child').chmod(0o755)
    (bound/'link').symlink_to('child')
    for name in ('swapped','gone'):
        (bound/name).write_bytes((root/'probe').read_bytes());(bound/name).chmod(0o755)
    (bound/'decoy').write_text('#!/nonexistent\n');(bound/'decoy').chmod(0o755)
    for name,body,mode in [('script','#!/mnt/child optional argument\n',0o755),('bad','invalid\n',0o755),('denied','invalid\n',0o644),('nested','#!/script\n',0o755),('loop','#!/loop\n',0o755)]:
        (root/name).write_text(body);(root/name).chmod(mode)
    (root/'truncated').write_bytes(b'\x7fELF');(root/'truncated').chmod(0o755)
    def check(name,op,path,expected,mode='compat',absent=()):
        cmd=[str(elf),'--mode',mode,'--root',str(root),'-v',f'{bound}:/mnt','--','./probe',op,path]
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15)
        results.append(dict(name=name,returncode=p.returncode,output=p.stdout))
        (build/'exec-results.json').write_text(json.dumps(results,indent=2))
        assert p.returncode==0,(name,p.stdout)
        for s in expected:assert s+'\n' in p.stdout,(name,s,p.stdout)
        for s in absent:assert s not in p.stdout,(name,s,p.stdout)
        print('PASS:',name,flush=True)
    common=['ARG=custom-zero','ARG=/mnt/file','ENV=PATH=/guest/bin','ENV=HOME=/guest','ROOT','BOUND','OPEN=0']
    check('exec preserves bind argv env','!v','/mnt/child',common+['CWD=/'])
    check('execveat directory FD','!a','child',common)
    check('exec preserves cwd','!c','child',common+['CWD=/mnt'])
    check('container exec preserves explicit environment','!v','/mnt/child',common,mode='container')
    check('empty environment','!z','/mnt/child',['ROOT','BOUND'],absent=['ENV='])
    check('script bound interpreter and single optional argument','!v','/script',['ARG=/mnt/child','ARG=optional argument','ARG=/script','ARG=/mnt/file','ROOT','BOUND'])
    check('exec follows symlink','!v','/mnt/link',common)
    check('execveat nofollow','!n','link',['RET=-40'])
    check('missing executable','!v','/missing',['RET=-2'])
    check('non executable','!v','/denied',['RET=-13'])
    check('invalid format','!v','/bad',['RET=-8'])
    check('truncated ELF rejected before replacing process','!v','/truncated',['RET=-8'])
    check('empty pathname','!v','',['RET=-2'])
    check('FD exec of a directory is EACCES like the kernel','!e','',['RET=-13'])
    check('fexecve runs the program the FD names','!f','/mnt/child',common)
    check('fexecve with AT_SYMLINK_NOFOLLOW on a regular file','!h','/mnt/child',common)
    # The FD's object, not its name: a later rename over the name or an
    # unlink must not change what runs.
    check('fexecve after the name was replaced','!g','/mnt/swapped',common)
    assert (bound/'swapped').read_text()=='#!/nonexistent\n'
    check('fexecve of a deleted file','!d','/mnt/gone',common)
    assert not (bound/'gone').exists()
    check('fexecve of an O_PATH symlink FD is EACCES','!s','/mnt/link',['RET=-13'])
    check('fexecve of a script behind O_CLOEXEC is ENOENT','!x','/script',['RET=-2'])
    # Kernel binfmt_script: each level prepends its interpreter line and file name.
    check('nested script interpreter','!v','/nested',['ARG=/mnt/child','ARG=optional argument','ARG=/script','ARG=/nested','ARG=/mnt/file','ROOT','BOUND'])
    check('self-interpreting script loops like the kernel','!v','/loop',['RET=-40'])
print(f'{len(results)} exec checks passed')
