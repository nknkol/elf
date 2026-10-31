#!/usr/bin/env python3
"""--isolate: the payload's host path calls are executed by the broker.

The same workload (reads, writes, directories, renames, symbolic and hard
links, chmod, stat, find, tar, exec chains and scripts) gives the same
output with and without the broker. Both builds."""
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
'''

with tempfile.TemporaryDirectory(prefix='isolate-', dir=lib.BUILD) as tmp:
    for suffix, loader in lib.loaders():
        outputs = []
        for options in (['--link-copy'], ['--link-copy', '--isolate']):
            work = Path(tmp) / f'work{suffix}{len(options)}'
            work.mkdir()
            p = lib.guest(loader, ['./bin/busybox', 'sh', '-c', SCRIPT], root=alpine,
                          volumes=[(work, '/work'), ('/dev/null', '/dev/null')], options=options)
            assert p.returncode == 0, (suffix, options, p.stdout, p.stderr[-1500:])
            outputs.append(p.stdout)
        assert outputs[0] == outputs[1], (suffix, outputs)
        print('PASS: the broker serves a file workload exactly like direct calls:', loader.name)
