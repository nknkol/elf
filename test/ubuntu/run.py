#!/usr/bin/env python3
"""Offline glibc rootfs survey. Exits nonzero if any acceptance case fails."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

REPO=Path(__file__).resolve().parents[2]
BUILD=lib.BUILD
spec=importlib.util.spec_from_file_location('rootfs_extract',REPO/'test/alpine/run.py')
extract=importlib.util.module_from_spec(spec);spec.loader.exec_module(extract)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    args=parser.parse_args();archive=args.archive.resolve(strict=True)
    loader=BUILD/'elfloader'
    manifest=json.loads((BUILD/'elfloader.json').read_text())
    assert hashlib.sha256(loader.read_bytes()).hexdigest()==manifest['sha256']
    report=dict(archive=archive.name,archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),loader_sha256=manifest['sha256'],hardlinks='materialized as regular copies; inode identity not tested',results=[])
    output=BUILD/'ubuntu-results.json'
    with tempfile.TemporaryDirectory(prefix='ubuntu-',dir=BUILD) as temp:
        work=Path(temp);root=work/'root';root.mkdir();bound=work/'bound';bound.mkdir()
        extract.extract_root(archive,root,materialize_hardlinks=True)
        (root/'workspace').mkdir(exist_ok=True);(bound/'input').write_text('BOUND\n')
        script=root/'tmp/accept-script';script.write_text('#!/bin/sh\nprintf "SCRIPT:%s:%s\\n" "$1" "$TEST_TOKEN"\n');script.chmod(0o755)
        report['os_release']=(root/'usr/lib/os-release').read_text()
        prefix=[str(loader),*lib.EXTRA,'--mode','container','--root',str(root),'-v',f'{bound}:/workspace','-v','/dev/null:/dev/null','--','./usr/bin/dash','-c']
        cases=[
            ('dash startup','printf GLIBC_OK','GLIBC_OK'),
            ('glibc version','getconf GNU_LIBC_VERSION',None),
            ('bash startup','bash --noprofile --norc -c "echo BASH_OK"','BASH_OK\n'),
            ('pipe and grep','printf "a\\nb\\n" | grep b','b\n'),
            ('GNU sed','printf abc | sed s/b/B/','aBc'),
            ('awk alternatives symlink','printf "x y\\n" | awk \'{print $2}\'','y\n'),
            ('Perl','perl -e \'print "PERL_OK\\n"\'','PERL_OK\n'),
            ('NSS local passwd','getent passwd root','root:x:0:0:root:/root:/bin/bash\n'),
            ('dpkg local database',"dpkg-query -W -f='${Status}\\n' libc6",'install ok installed\n'),
            ('background and wait','(printf CHILD) & wait; printf WAITED','CHILDWAITED'),
            ('find directory traversal','find /tmp -maxdepth 0','/tmp\n'),
            ('nested shell exit','/bin/sh -c "exit 7"; printf "STATUS:%s\\n" "$?"','STATUS:7\n'),
            ('script argv and env','TEST_TOKEN=kept; export TEST_TOKEN; /tmp/accept-script arg','SCRIPT:arg:kept\n'),
            ('bind cwd and file read','cd /workspace; /bin/sh -c \'pwd; read v < input; printf "%s\\n" "$v"\'','/workspace\nBOUND\n'),
            ('bind write','printf output > /workspace/output; read v < /workspace/output; printf "%s" "$v"','output'),
            ('command substitution','v=$(getconf GNU_LIBC_VERSION); printf "%s\\n" "$v"',None),
            ('Rust coreutils ls','/usr/bin/ls /etc/os-release','/etc/os-release\n'),
            ('Rust coreutils cat','/usr/bin/cat /workspace/input','BOUND\n'),
        ]
        for name,command,expected in cases:
            try:
                p=subprocess.run(prefix+['PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; '+command],capture_output=True,text=True,timeout=20)
                ok=p.returncode==0 and (p.stdout==expected if expected is not None else p.stdout.startswith('glibc '))
                item=dict(name=name,status='passed' if ok else 'failed',returncode=p.returncode,stdout=p.stdout,stderr=p.stderr)
                if not ok and 'rustix/src/backend/linux_raw/param/auxv.rs' in p.stderr:
                    item['failure_signature']='rustix auxv initialization panic; root cause unresolved'
                if name=='bind write' and ok:
                    assert (bound/'output').read_text()=='output'
            except subprocess.TimeoutExpired:
                item=dict(name=name,status='timeout')
            report['results'].append(item);output.write_text(json.dumps(report,indent=2)+'\n')
            print(item['status'].upper()+': '+name,flush=True)
    passed=sum(r['status']=='passed' for r in report['results'])
    print(f'{passed}/{len(report["results"])} Ubuntu cases passed; report: {output}')
    return 0 if passed==len(report['results']) else 1


if __name__=='__main__':raise SystemExit(main())
