#!/usr/bin/env python3
"""End-to-end SVC -> ELF payload -> PRoot core -> host filesystem tests."""
from pathlib import Path
import errno,json,os,subprocess,tempfile,selectors,hashlib
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
here = Path(__file__).resolve().parent
elf = lib.loader()
build=lib.BUILD
build.mkdir(exist_ok=True)
results=[]
with tempfile.TemporaryDirectory(prefix='svc-fixture-',dir=build) as temp:
    work=Path(temp);root=work/'root';bound=work/'bound'
    for p in (root/'real/sub',root/'mnt',root/'old',root/'proc',bound):p.mkdir(parents=True,exist_ok=True)
    for p,data in [(root/'real/file','ROOT\n'),(root/'plain','PLAIN\n'),(root/'old/file','RENAMED\n'),(bound/'file','BOUND\n')]:p.write_text(data)
    (root/'link').symlink_to('real/sub')
    (root/'absolute').symlink_to('/real/file')
    (root/'loop1').symlink_to('loop2');(root/'loop2').symlink_to('loop1')
    (root/'proc/link').symlink_to('/real/file')
    (bound/'absolute').symlink_to('/real/file');(bound/'relative').symlink_to('file')
    probe=root/'probe'
    subprocess.run([*lib.PROBE,str(here/'svc_open_probe.c'),'-o',str(probe)],check=True)
    meta=root/'meta'
    subprocess.run([*lib.PROBE,str(here/'svc_meta_probe.c'),'-o',str(meta)],check=True)
    mutation=root/'mutation'
    subprocess.run([*lib.PROBE,str(here/'svc_mutate_probe.c'),'-o',str(mutation)],check=True)
    controls=[]
    for op in ['e','i','x']:
        native=subprocess.run([str(meta),op,str(root/'absolute'),'0'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15)
        controls.append(dict(operation=op,returncode=native.returncode,output=native.stdout))
    (build/'native-metadata-controls.json').write_text(json.dumps(controls,indent=2))
    prefix=[str(elf),'--mode','compat','--root',str(root),'-v',f'{bound}:/mnt','--','./probe']
    def check(name,path,flags=0,*,expected=0,data=None,directory=None,rename=None):
        cmd=prefix+[path,str(flags)]
        if directory:cmd.append(directory)
        if rename:cmd.append(rename)
        if rename:
            with subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as child:
                prefix_output=b''
                try:
                    with selectors.DefaultSelector() as sel:
                        sel.register(child.stdout,selectors.EVENT_READ)
                        while b'READY\n' not in prefix_output:
                            if not sel.select(15):raise TimeoutError('guest FD-open handshake')
                            chunk=os.read(child.stdout.fileno(),4096)
                            if not chunk:raise RuntimeError(prefix_output.decode())
                            prefix_output+=chunk
                    os.rename(root/directory.lstrip('/'),root/rename.lstrip('/'))
                    suffix,_=child.communicate(b'x',timeout=15)
                    p=subprocess.CompletedProcess(cmd,child.returncode,(prefix_output+suffix).decode())
                finally:
                    if child.poll() is None:child.kill();child.wait()
        else:
            p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15)
        result=dict(name=name,returncode=p.returncode,output=p.stdout)
        results.append(result)
        (build/'svc-results.json').write_text(json.dumps(results,indent=2))
        assert p.returncode==0,(name,p.stdout)
        assert f'OPEN={expected}\n' in p.stdout,(name,p.stdout)
        if rename:
            for operation in ['CWD_RET','FCHDIR_RET','CWD_OPEN']:
                assert f'{operation}={expected}\n' in p.stdout,(name,p.stdout)
        if data is not None:assert f'DATA={data}\n' in p.stdout,(name,p.stdout)
        print('PASS:',name,flush=True)
    check('guest absolute path','/real/file',data='ROOT')
    check('cwd relative path','real/file',data='ROOT')
    check('symlink before dotdot','/link/../file',data='ROOT')
    check('absolute symlink uses guest root','/absolute',data='ROOT')
    check('bind','/mnt/file',data='BOUND')
    check('absolute link inside bind','/mnt/absolute',data='ROOT')
    check('relative link inside bind','/mnt/relative',data='BOUND')
    check('directory fd','file',directory='/real',data='ROOT')
    check('bind directory fd','file',directory='/mnt',data='BOUND')
    check('directory fd survives host rename','file',directory='/old',rename='/renamed',data='RENAMED')
    # The FD still refers to root/mnt/hidden, but /mnt maps to bound.
    # Never silently read bound/hidden/file through that old directory FD.
    (root/'to-hide').mkdir()
    (root/'to-hide/file').write_text('ORIGINAL\n')
    (bound/'hidden').mkdir()
    (bound/'hidden/file').write_text('WRONG-OBJECT\n')
    check('directory fd renamed behind bind is rejected','file',
          directory='/to-hide',rename='/mnt/hidden',expected=-errno.EXDEV)
    check('nofollow final symlink','/absolute',flags=os.O_NOFOLLOW,expected=-errno.ELOOP)
    check('exclusive create on symlink','/absolute',flags=os.O_CREAT|os.O_EXCL|os.O_WRONLY,expected=-errno.EEXIST)
    check('create missing final','/created',flags=os.O_CREAT|os.O_WRONLY)
    assert (root/'created').exists()
    check('missing intermediate','/missing/file',expected=-errno.ENOENT)
    check('non-directory intermediate','/plain/file',expected=-errno.ENOTDIR)
    check('trailing slash','/plain/',expected=-errno.ENOTDIR)
    check('symlink loop','/loop1',expected=-errno.ELOOP)
    # PRoot readlink_proc: a non-special name under /proc resolves like any link.
    check('ordinary link under /proc resolves like PRoot','/proc/link',data='ROOT')
    def metadata(name,op,path,value=0,expected=()):
        cmd=prefix[:-1]+['./meta',op,path,str(value)]
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15)
        results.append(dict(name=name,returncode=p.returncode,output=p.stdout))
        (build/'svc-results.json').write_text(json.dumps(results,indent=2))
        assert p.returncode==0,(name,p.stdout)
        for line in expected:assert line+'\n' in p.stdout,(name,line,p.stdout)
        print('PASS:',name,flush=True)
    metadata('stat follows guest absolute symlink','s','/absolute',expected=['RET=0','TYPE=32768','SIZE=5'])
    metadata('lstat preserves symlink identity','s','/absolute',256,expected=['RET=0','TYPE=40960','SIZE=10'])
    metadata('stat bound file','s','/mnt/file',expected=['RET=0','SIZE=6'])
    metadata('stat missing file','s','/missing',expected=['RET=-2'])
    metadata('stat into a bad buffer is EFAULT','u','/real/file',expected=['RET=-14'])
    metadata('stat via symlink into a bad buffer is EFAULT','u','/absolute',expected=['RET=-14'])
    metadata('stat empty path without flag','s','',expected=['RET=-2'])
    metadata('stat empty path with symlink FD','e','/absolute',expected=['RET=0','TYPE=40960'])
    metadata('stat empty path with nofollow FD','e','/absolute',256,expected=['RET=0','TYPE=40960'])
    metadata('fstat symlink FD reference','i','/absolute',expected=['RET=0','TYPE=40960'])
    metadata('statx follows guest symlink','t','/absolute',expected=['RET=0','TYPE=32768','SIZE=5'])
    metadata('statx nofollow','t','/absolute',256,expected=['RET=0','TYPE=40960'])
    metadata('statx empty path symlink FD','x','/absolute',expected=['RET=0','TYPE=40960'])
    metadata('stat empty path invalid flags','e','/absolute',536870912,expected=['RET=-22'])
    metadata('readlink preserves absolute guest target','r','/absolute',255,expected=['RET=10','LINK=/real/file','AFTER=90'])
    metadata('readlink preserves relative target','r','/mnt/relative',255,expected=['RET=4','LINK=file','AFTER=90'])
    metadata('readlink truncates without NUL','r','/absolute',3,expected=['RET=3','LINK=/re','AFTER=90'])
    metadata('readlink zero capacity','r','/absolute',0,expected=['RET=-22'])
    metadata('readlink regular file','r','/plain',255,expected=['RET=-22'])
    metadata('readlink via empty pathname FD','q','/absolute',255,expected=['RET=10','LINK=/real/file','AFTER=90'])
    metadata('readlink ordinary link under /proc','r','/proc/link',255,expected=['RET=10','LINK=/real/file'])
    metadata('getcwd root includes NUL in result','g','/',255,expected=['RET=2','CWD=/','TERMINATOR=0'])
    metadata('chdir updates relative open and cwd','c','/real',255,expected=['CHDIR=0','RET=6','CWD=/real','OPEN=0','DATA=ROOT'])
    metadata('chdir bound directory','c','/mnt',255,expected=['CHDIR=0','RET=5','CWD=/mnt','DATA=BOUND'])
    metadata('chdir follows guest symlink','c','/link',255,expected=['CHDIR=0','RET=10','CWD=/real/sub'])
    metadata('fchdir bound directory','f','/mnt',255,expected=['CHDIR=0','RET=5','CWD=/mnt','DATA=BOUND'])
    metadata('failed chdir keeps cwd','c','/missing',255,expected=['CHDIR=-2','RET=2','CWD=/'])
    metadata('failed fchdir keeps cwd','f','/plain',255,expected=['CHDIR=-20','RET=2','CWD=/'])
    metadata('getcwd insufficient buffer','c','/real',5,expected=['CHDIR=0','RET=-34'])
    metadata('getcwd exact buffer','c','/real',6,expected=['CHDIR=0','RET=6','CWD=/real','TERMINATOR=0'])
    metadata('faccessat follows guest symlink','a','/absolute',expected=['RET=0'])
    metadata('faccessat2 follows guest symlink','b','/absolute',expected=['RET=0'])
    metadata('faccessat missing','a','/missing',expected=['RET=-2'])
    def mutate(name,op,source,destination='',value=0,*,expected=0,olddir='-',newdir='-',extra_bind=None):
        options=prefix[:-2]
        if extra_bind: options=options+['-v',extra_bind]
        cmd=options+['--','./mutation',op,source,destination,str(value),olddir,newdir]
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15)
        results.append(dict(name=name,returncode=p.returncode,output=p.stdout))
        (build/'svc-results.json').write_text(json.dumps(results,indent=2))
        assert p.returncode==0,(name,p.stdout)
        assert f'RET={expected}\n' in p.stdout,(name,p.stdout)
        print('PASS:',name,flush=True)
    mutate('mkdir within root','m','/newdir',value=0o750)
    assert (root/'newdir').is_dir()
    mutate('mkdir relative to bound dirfd','m','newdir',value=0o750,olddir='/mnt')
    assert (bound/'newdir').is_dir()
    mutate('mkdir existing directory','m','/newdir',value=0o750,expected=-errno.EEXIST)
    mutate('mkdir missing parent','m','/absent/dir',value=0o750,expected=-errno.ENOENT)
    mutate('symlink absolute target is opaque','s','/real/file','/newdir/absolute')
    assert os.readlink(root/'newdir/absolute')=='/real/file'
    check('read created absolute symlink','/newdir/absolute',data='ROOT')
    mutate('symlink relative to directory FD','s','../file','relative',olddir='/mnt/newdir')
    assert os.readlink(bound/'newdir/relative')=='../file'
    check('read created relative symlink','/mnt/newdir/relative',data='BOUND')
    mutate('symlink dangling target allowed','s','/does-not-exist','/newdir/dangling')
    assert os.readlink(root/'newdir/dangling')=='/does-not-exist'
    mutate('symlink existing destination','s','unused','/newdir/absolute',expected=-errno.EEXIST)
    mutate('unlink symlink not referent','u','/newdir/absolute')
    assert not (root/'newdir/absolute').is_symlink() and (root/'real/file').read_text()=='ROOT\n'
    mutate('unlink directory without removedir','u','/newdir',expected=-errno.EISDIR)
    mutate('rmdir nonempty directory','u','/newdir',value=512,expected=-errno.ENOTEMPTY)
    mutate('rmdir bound child','u','/mnt/newdir/relative')
    mutate('rmdir empty bound child','u','/mnt/newdir',value=512)
    assert not (bound/'newdir').exists()
    (root/'newdir/source').write_text('MOVE\n')
    mutate('rename two relative directory FDs','r','source','moved',olddir='/newdir',newdir='/real')
    assert not (root/'newdir/source').exists() and (root/'real/moved').read_text()=='MOVE\n'
    mutate('rename symlink itself','r','/newdir/dangling','/newdir/renamed-link')
    assert os.readlink(root/'newdir/renamed-link')=='/does-not-exist'
    (root/'newdir/target-link').symlink_to('/real/file')
    (root/'newdir/replacement').write_text('REPLACED\n')
    mutate('rename replaces destination symlink','r','/newdir/replacement','/newdir/target-link')
    assert not (root/'newdir/target-link').is_symlink() and (root/'real/file').read_text()=='ROOT\n'
    # Compare with the native host: this sandbox currently rejects hardlinks
    # with EPERM. A rejection check is NOT successful hardlink validation.
    hardlink_controls=[]
    def native_link(source,destination,flags=0):
        cmd=[str(mutation),'l',str(source),str(destination),str(flags),'-','-']
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15)
        assert p.returncode==0,p.stdout
        rc=int(next(line[4:] for line in p.stdout.splitlines() if line.startswith('RET=')))
        hardlink_controls.append(dict(source=source.name,flags=flags,result=rc))
        (build/'native-hardlink-controls.json').write_text(json.dumps(hardlink_controls,indent=2))
        return rc
    regular_rc=native_link(root/'real/file',root/'native-hard')
    symlink_rc=native_link(root/'absolute',root/'native-hard-symlink')
    # A native relative symlink can resolve inside the fixture without chroot.
    (root/'native-relative').symlink_to('real/file')
    follow_rc=native_link(root/'native-relative',root/'native-hard-follow',1024)
    bound_rc=native_link(bound/'file',bound/'native-hard')
    # Without --link-copy every hard link matches the host, refusal included.
    def linked(name,rc,source,target,old,new,follow=False,value=0,**kw):
        mutate(name,'l',old,new,value=value,expected=rc,**kw)
        stat=(lambda p:p.stat()) if follow or not source.is_symlink() else (lambda p:p.lstat())
        if rc==0:assert stat(source).st_ino==stat(target).st_ino
        else:assert not target.exists() and not target.is_symlink()
    linked('hardlink within root matches host',regular_rc,root/'real/file',root/'newdir/hard','/real/file','/newdir/hard')
    linked('hardlink symlink matches host',symlink_rc,root/'absolute',root/'newdir/hard-symlink','/absolute','/newdir/hard-symlink')
    linked('hardlink follows guest symlink before host call',follow_rc,root/'real/file',root/'newdir/hard-follow','/absolute','/newdir/hard-follow',follow=True,value=1024)
    linked('hardlink two bound directory FDs matches host',bound_rc,bound/'file',bound/'hard','file','hard',olddir='/mnt',newdir='/mnt')
    mutate('rename cross bind refused','r','/real/moved','/mnt/cross',expected=-errno.EXDEV)
    assert (root/'real/moved').exists() and not (bound/'cross').exists()
    mutate('hardlink cross bind refused','l','/real/file','/mnt/cross',expected=-errno.EXDEV)
    assert not (bound/'cross').exists()
    mutate('distinct binds of same host remain separate mounts','l','/mnt/file','/alias/cross',extra_bind=f'{bound}:/alias',expected=-errno.EXDEV)
    assert not (bound/'cross').exists()
    (bound/'nested').mkdir()
    mutate('nested bind crossing refused','r','/mnt/file','/mnt/nested/cross',extra_bind=f'{bound}/nested:/mnt/nested',expected=-errno.EXDEV)
    assert (bound/'file').exists() and not (bound/'nested/cross').exists()
    mutate('bind mountpoint rename refused','r','/mnt','/moved-mount',expected=-errno.EBUSY)
    mutate('bind mountpoint rmdir refused','u','/mnt',value=512,expected=-errno.EBUSY)
    mutate('root rename refused','r','/','/new-root',expected=-errno.EBUSY)
    mutate('empty-path hardlink explicitly unsupported','l','','/newdir/empty-link',value=4096,expected=-errno.EOPNOTSUPP)
    (root/'newdir/a').write_text('A');(root/'newdir/b').write_text('B')
    mutate('renameat2 noreplace','R','/newdir/a','/newdir/b',value=1,expected=-errno.EEXIST)
    assert (root/'newdir/a').read_text()=='A' and (root/'newdir/b').read_text()=='B'
    mutate('renameat2 exchange','R','/newdir/a','/newdir/b',value=2)
    assert (root/'newdir/a').read_text()=='B' and (root/'newdir/b').read_text()=='A'
    print(f'{len(results)} SVC integration checks passed.')
