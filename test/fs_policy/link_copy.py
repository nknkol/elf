#!/usr/bin/env python3
"""--link-copy: hard links on storage that refuses them become copies.

dpkg backs up its database with link(); HarmonyOS shared storage and
Android FUSE refuse every hard link. Opt-in only: by default the host's
error stands. Where the host allows links, the kernel's real link is kept
(shared inode). Both builds."""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: link rootfs unavailable:', alpine)
    raise SystemExit(0)

SCRIPT = ('cd /work && printf data > file && chmod 640 file && ln file copy && '
          'echo "read=$(cat copy)" && echo "mode=$(stat -c %a copy)" && '
          'ln -s file sym && ln sym symcopy && echo "link=$(readlink symcopy)" && '
          'ln file copy 2>/dev/null; echo "again=$?"; ln missing other 2>/dev/null; echo "missing=$?"')
with tempfile.TemporaryDirectory(prefix='link-copy-', dir=build) as tmp:
    probe = Path(tmp) / 'probe'
    probe.write_text('x')
    try:
        os.link(probe, Path(tmp) / 'probe-link')
        native = 'link'
    except PermissionError:  # EPERM or EACCES on storage that refuses links.
        native = 'copy'
    for suffix in ('', '-guarded'):
        loader = lib.loader(suffix)
        if native == 'copy':
            # Default: the host's refusal stands, nothing is created.
            work = Path(tmp) / f'plain{suffix}'
            work.mkdir()
            p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                                '-v', f'{work}:/work', '--', './bin/busybox', 'sh', '-c',
                                'cd /work && echo x > file && ln file copy; echo "rc=$?"'],
                               cwd=alpine, capture_output=True, text=True, timeout=60)
            assert p.stdout.strip().endswith('rc=1') and not (work / 'copy').exists(), (
                suffix, p.stdout)
        work = Path(tmp) / f'work{suffix}'
        work.mkdir()
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                            '--link-copy', '-v', f'{work}:/work', '--', './bin/busybox', 'sh', '-c',
                            SCRIPT + '; /bin/busybox sh -c "ln file copy2" && echo "child=ok"'],
                           cwd=alpine, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, (suffix, p.stdout, p.stderr[-1500:])
        values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
        # child=ok: the option survives the exec chain.
        assert values == {'read': 'data', 'mode': '640', 'link': 'file', 'again': '1',
                          'missing': '1', 'child': 'ok'}, (suffix, values)
        same = (work / 'file').stat().st_ino == (work / 'copy').stat().st_ino
        assert same == (native == 'link'), (suffix, native, same)
        print(f'PASS: hard links ({native} on this storage):', loader.name)
