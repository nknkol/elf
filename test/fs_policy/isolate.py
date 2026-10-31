#!/usr/bin/env python3
"""--isolate: the payload's host path calls are executed by the broker.

The same workload (reads, writes, directories, renames, symbolic and hard
links, chmod, stat, find, tar, exec chains and scripts, UNIX sockets, FDs
the guest tries to close) gives the same output with and without the
broker. Under the guest filter a kernel call issued from the payload's own
svc instruction cannot open a host path. Both builds. The acceptance
criteria are in docs/ISOLATION_TESTING.md."""
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

alpine = lib.require(lib.ALPINE / 'bin/busybox').parents[1]
SCRIPT = r'''
set -e
cd /work
cat /etc/alpine-release
echo data > file; cat file
mkdir -p dir/sub; echo nested > dir/sub/n; ls dir dir/sub
mv file renamed; ls
ln -s renamed link; readlink link; cat link
ln renamed hard; stat -c '%h %s' hard
chmod 640 renamed; stat -c '%a' renamed
touch -d '2001-02-03 04:05:06' renamed; stat -c '%Y' renamed
find dir | sort
tar cf t.tar dir; tar tf t.tar | sort
printf '#!/bin/sh\necho script "$@"\n' > s.sh; chmod +x s.sh; ./s.sh a b
/bin/busybox sh -c 'echo child $(cat /work/dir/sub/n)'
cd dir && pwd && cat sub/n && cd ..
rm -r dir t.tar hard link; ls
test -e /etc/passwd && echo passwd
ls /nonexistent 2>/dev/null || echo missing
exec 898<&- 899<&- 900<&-; cat /etc/alpine-release
/work/probe s /work/sock
stat -c %F /proc/self/fd/0 >/dev/null && echo fd-stat
'''



def socket_capable():
    """Some backings refuse socket inodes (HarmonyOS /storage/Users, /tmp)."""
    for base in (lib.BUILD, Path(tempfile.gettempdir()), Path('/data/storage/el2/base/cache')):
        try:
            with tempfile.TemporaryDirectory(prefix='sock-probe-', dir=base) as tmp:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.bind(str(Path(tmp) / 's'))
            return base
        except OSError:
            continue
    raise SystemExit('no backing directory accepts UNIX socket files')


with tempfile.TemporaryDirectory(prefix='isolate-', dir=socket_capable()) as tmp:
    probe = lib.build_probe(Path(__file__).with_name('isolate_probe.c'), Path(tmp) / 'probe',
                            '-I', str(lib.REPO / 'src/payload/include'))
    for suffix, loader in lib.loaders():
        outputs = []
        for options in (['--link-copy'], ['--link-copy', '--isolate']):
            work = Path(tmp) / f'work{suffix}{len(options)}'
            work.mkdir()
            shutil.copy2(probe, work / 'probe')
            p = lib.guest(loader, ['./bin/busybox', 'sh', '-c', SCRIPT], root=alpine,
                          volumes=[(work, '/work'), ('/dev/null', '/dev/null'), ('/proc', '/proc')],
                          options=options,
                          stdin=subprocess.DEVNULL)
            assert p.returncode == 0, (suffix, options, p.stdout, p.stderr[-1500:])
            outputs.append(p.stdout)
        assert outputs[0] == outputs[1], (suffix, outputs)
        print('PASS: the broker serves a file workload exactly like direct calls:', loader.name)

    target = alpine / 'etc/alpine-release'
    for suffix, loader in lib.loaders():
        for isolate, expected in ((False, 'direct=0'), (True, 'direct=-1')):
            # Not lib.guest: the comparison needs a run without the filter.
            argv = [str(loader), '--mode', 'container', '--root', str(alpine), '-v', f'{tmp}:/t',
                    *(['--isolate'] if isolate else []), '--', './bin/busybox', 'sh', '-c',
                    f'/t/probe f {target}']
            p = subprocess.run(argv, cwd=alpine, capture_output=True, text=True, timeout=60)
            assert p.returncode == 0 and expected in p.stdout.split(), (suffix, isolate, p.stdout, p.stderr)
        print('PASS: under the guest filter the payload\'s own svc cannot open a host path:', loader.name)
