#!/usr/bin/env python3
"""Binds below directories missing from the root (PRoot glue), both backends."""
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
    print('SKIP: glue rootfs unavailable:', alpine)
    raise SystemExit(0)
assert not (alpine / 'glue').exists()
SCRIPT = ('echo "read=$(cat /glue/deep/w/f)"; echo "type=$(stat -c %F /glue/deep)"; '
          '[ -d /glue ] && echo "dir=yes"; [ -x /glue/deep ] && echo "search=yes"; '
          'echo "rel=$(cd / && cat glue/deep/../deep/w/f)"; '
          'cat /glue/missing 2>/dev/null || echo "other=absent"; '
          # Glue directories open, list and can be entered, like PRoot's.
          'echo "list=$(ls /glue)/$(echo $(ls /glue/deep))"; '
          'echo "pwd=$(cd /glue/deep && pwd -P)"; echo "cat=$(cd /glue/deep && cat w/f)"; '
          'mkdir -p /glue/deep/w && echo "mkdirp=ok"; '
          'echo "proc=$(cd /glue && readlink /proc/self/cwd)"; '
          'echo "up=$(cd /glue/deep && cd .. && ls)"; '
          'mkdir /glue/new 2>/dev/null && echo "mkdir=created" || echo "mkdir=refused"; '
          'touch /glue/deep/file 2>/dev/null && echo "touch=created" || echo "touch=refused"; '
          'chmod 777 /glue 2>/dev/null && echo "chmod=changed" || echo "chmod=refused"; '
          'echo "owner=$(stat -c %u /glue)"')
with tempfile.TemporaryDirectory(prefix='glue-', dir=build) as tmp:
    (Path(tmp) / 'f').write_text('bound\n')
    base = Path(tmp) / 'base'
    base.mkdir()
    for suffix, options in (('', []), ('-guarded', []),
                            ('-guarded', ['--guard-file-access', 'rrrr',
                                                '--allow-stdio-output', '--allow-pipe-output',
                                                '--revalidate-file-fds'])):
        loader = lib.loader(suffix)
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine),
                            '-v', '/proc:/proc', '-v', f'{tmp}/f:/glue/deep/w2/file',
                            '-v', f'{tmp}:/glue/deep/w', *options, '--', './bin/busybox', 'sh',
                            '-c', SCRIPT], cwd=alpine, capture_output=True, text=True, timeout=60,
                           env={**os.environ, 'PROOT_TMP_DIR': str(base)})
        assert p.returncode == 0, (suffix, options, p.stdout, p.stderr[-1500:])
        values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
        assert values == {'read': 'bound', 'type': 'directory', 'dir': 'yes', 'search': 'yes',
                          'rel': 'bound', 'other': 'absent', 'list': 'deep/w w2',
                          'pwd': '/glue/deep', 'cat': 'bound', 'mkdirp': 'ok', 'proc': '/glue', 'up': 'deep',
                          'mkdir': 'refused', 'touch': 'refused', 'chmod': 'refused',
                          'owner': '0'}, (suffix, options, values)
        print('PASS: binds below missing directories:', loader.name, 'guarded' if options else 'plain')
    assert not (alpine / 'glue').exists(), 'glue must not create host directories'
    # One sealed tree per view, shared by every process; no build leftovers.
    trees = sorted(p.name for p in base.iterdir())
    assert len(trees) == 1 and trees[0].startswith('proot-glue-'), trees
    tree = base / trees[0]
    assert sorted(str(p.relative_to(tree)) for p in tree.rglob('*')) == [
        'glue', 'glue/deep', 'glue/deep/w', 'glue/deep/w2', 'glue/deep/w2/file', 'proc'], list(tree.rglob('*'))
    for path in [tree, *tree.rglob('*')]:
        if path.is_dir():
            assert not path.stat().st_mode & 0o022, path
            path.chmod(0o755)
