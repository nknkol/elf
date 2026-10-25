#!/usr/bin/env python3
"""Offline Alpine acceptance using a user-supplied AArch64 minirootfs archive."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

REPO=Path(__file__).resolve().parents[2]
BUILD=REPO/'vendor/proot/svc/build'


def extract_root(archive, root, *, materialize_hardlinks=False):
    # Rootfs absolute symlinks are guest paths, so tarfile's data filter rejects
    # valid BusyBox applets. Validate all member paths and create links LAST.
    # No archive member may be written through a symlink, even a later one.
    with tarfile.open(archive) as tar:
        members=tar.getmembers()
        links=set();seen=set();total=0
        for member in members:
            path=PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or path in seen:
                raise ValueError(f'Unsafe or duplicate archive member: {member.name}')
            seen.add(path)
            if not (member.isdir() or member.isfile() or member.issym() or (materialize_hardlinks and member.islnk())):
                raise ValueError(f'Unsupported archive member type: {member.name}')
            if member.issym(): links.add(path)
            total+=member.size
        if total>256*1024*1024:raise ValueError('Fixture exceeds 256 MiB extraction limit')
        for member in members:
            path=PurePosixPath(member.name)
            if any(parent in links for parent in path.parents):
                raise ValueError(f'Archive member beneath a symlink: {member.name}')
        regular={PurePosixPath(m.name):m for m in members if m.isfile()}
        hardlinks=[m for m in members if m.islnk()]
        expanded=total
        for member in hardlinks:
            target=PurePosixPath(member.linkname)
            if target.is_absolute() or '..' in target.parts or target not in regular:
                raise ValueError(f'Hardlink must target an archive regular file: {member.name}')
            expanded+=regular[target].size
        if expanded>2*1024*1024*1024:raise ValueError('Expanded hardlink fixture exceeds 2 GiB')
        for member in members:
            dest=root/PurePosixPath(member.name)
            if member.isdir():dest.mkdir(parents=True,exist_ok=True)
            elif member.isfile():
                dest.parent.mkdir(parents=True,exist_ok=True)
                with tar.extractfile(member) as src,dest.open('xb') as out:
                    shutil.copyfileobj(src,out)
                dest.chmod(member.mode & 0o777)
        # The host denies hardlink creation. Explicit opt-in materializes file
        # bytes; this fixture cannot validate shared-inode/hardlink semantics.
        for member in hardlinks:
            target=PurePosixPath(member.linkname)
            dest=root/PurePosixPath(member.name)
            dest.parent.mkdir(parents=True,exist_ok=True)
            with (root/target).open('rb') as src,dest.open('xb') as out:
                shutil.copyfileobj(src,out)
            dest.chmod(regular[target].mode & 0o777)
        for member in members:
            if member.issym():
                dest=root/PurePosixPath(member.name)
                dest.parent.mkdir(parents=True,exist_ok=True)
                dest.symlink_to(member.linkname)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    args=parser.parse_args()
    archive=args.archive.resolve(strict=True)
    loader=BUILD/'elfloader-proot'
    manifest=json.loads((BUILD/'elf-build.json').read_text())
    assert hashlib.sha256(loader.read_bytes()).hexdigest()==manifest['sha256'],'Rebuild loader snapshot'
    report=dict(archive=archive.name,archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),loader_sha256=manifest['sha256'],results=[])
    output=BUILD/'alpine-results.json'
    with tempfile.TemporaryDirectory(prefix='alpine-',dir=BUILD) as temp:
        work=Path(temp);root=work/'root';root.mkdir();bound=work/'bound';bound.mkdir()
        extract_root(archive,root)
        (root/'workspace').mkdir(exist_ok=True)
        (bound/'input').write_text('BOUND\n')
        release=(root/'etc/alpine-release').read_text().strip()
        report['release']=release
        script=root/'tmp/accept-script'
        script.write_text('#!/bin/sh\nprintf "SCRIPT:%s:%s\\n" "$1" "$TEST_TOKEN"\n')
        script.chmod(0o755)
        prefix=[str(loader),'--mode','container','--root',str(root),'-v',f'{bound}:/workspace','-v','/dev/null:/dev/null','--','./bin/busybox']
        def check(name,argv,expected,rc=0):
            p=subprocess.run(prefix+argv,capture_output=True,text=True,timeout=20)
            item=dict(name=name,returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
            report['results'].append(item);output.write_text(json.dumps(report,indent=2)+'\n')
            assert p.returncode==rc,(name,item)
            assert p.stdout==expected,(name,item)
            print('PASS:',name,flush=True)
        def shell(name,command,expected,rc=0):
            check(name,['sh','-c','PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; '+command],expected,rc)
        check('musl dynamic BusyBox',['echo','ALPINE_OK'],'ALPINE_OK\n')
        shell('shell cwd and release','pwd; cat /etc/alpine-release','/\n'+release+'\n')
        shell('absolute applet symlink exec','/bin/cat /etc/alpine-release',release+'\n')
        shell('PATH lookup exec','cat /etc/alpine-release',release+'\n')
        shell('pipe','printf abc | /usr/bin/wc -c','3\n')
        shell('command substitution','v=$(cat /etc/alpine-release); printf "VALUE:%s\\n" "$v"','VALUE:'+release+'\n')
        shell('background child and wait','( /bin/busybox sleep 0.01; echo CHILD ) & wait; echo WAITED','CHILD\nWAITED\n')
        shell('nested shell and exit status','/bin/sh -c "exit 7"; printf "STATUS:%s\\n" "$?"','STATUS:7\n')
        shell('script interpreter and environment','TEST_TOKEN=kept; export TEST_TOKEN; /tmp/accept-script arg','SCRIPT:arg:kept\n')
        shell('bind across exec','/bin/sh -c "cat /workspace/input"','BOUND\n')
        shell('bind writes and rename','printf output > /workspace/a && mv /workspace/a /workspace/output && cat /workspace/output','output')
        assert (bound/'output').read_text()=='output' and not (bound/'a').exists()
        shell('cwd survives exec','cd /workspace && /bin/sh -c "pwd; cat input"','/workspace\nBOUND\n')
        shell('directory traversal','mkdir -p /tmp/tree/sub; touch /tmp/tree/sub/file; find /tmp/tree -type f','/tmp/tree/sub/file\n')
        shell('symlink target guest root','ln -s /etc/alpine-release /tmp/release; readlink /tmp/release; cat /tmp/release','/etc/alpine-release\n'+release+'\n')
        shell('archive roundtrip','mkdir /tmp/unpack; tar -cf /tmp/test.tar -C /workspace input && tar -xf /tmp/test.tar -C /tmp/unpack && cat /tmp/unpack/input','BOUND\n')
        shell('truncate through shell redirect','printf abcdef > /tmp/trunc; : > /tmp/trunc; wc -c < /tmp/trunc','0\n')
        p=subprocess.run(prefix+['sh','-c','/sbin/apk --version'],capture_output=True,text=True,timeout=20)
        report['results'].append(dict(name='apk dynamic dependencies',returncode=p.returncode,stdout=p.stdout,stderr=p.stderr))
        output.write_text(json.dumps(report,indent=2)+'\n')
        assert p.returncode==0 and 'apk-tools ' in p.stdout and 'aarch64' in p.stdout,p
        print('PASS: apk dynamic dependencies')
        shell('apk local database','/sbin/apk info -e busybox','busybox\n')
    print(f"{len(report['results'])} Alpine checks passed; report: {output}")


if __name__=='__main__':main()
