#!/usr/bin/env python3
"""A denied root under --isolate (docs/ISOLATION.md, "执行可信链" and the
broker's traversal rule; part of the application sandbox's acceptance
suite).

The root is denied ('d'), a volume is mounted at /mnt/vol. The broker lets
the guest pass through /, /mnt (stat, chdir) to reach the volume. Reading
the names of such a directory is a capability of its own: the probe opens
it through the payload (the broker answers) and lists the FD from the
payload's own svc, skipping the payload's filter.

Expected, guarded build with --isolate:
  - a root that also holds a hidden file: stat of / and chdir to /mnt
    succeed, the volume's file reads; opening / for reading and an inotify
    watch on / are refused (EACCES), so the hidden name never reaches the
    guest; the same for /mnt when it holds a hidden name;
  - a skeleton root (only the mount's ancestors and the exec helper):
    the listing works and shows only those names."""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

EACCES = -13
failures = []
loader = lib.BUILD / 'elfloader-guarded'
if not loader.exists():
    print('SKIP: elfloader-guarded missing')
    sys.exit(0)


def check(tag, ok, detail=''):
    print('PASS:' if ok else 'FAIL:', tag, '' if ok else detail)
    if not ok:
        failures.append(tag)


def parse(output):
    values, names = {}, None
    for line in output.splitlines():
        if line.startswith('names='):
            names = [n for n in line[6:].split(',') if n]
            continue
        parts = line.rsplit(' ', 1)
        if len(parts) == 2:
            try:
                values[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return values, names


with tempfile.TemporaryDirectory(prefix='iso-traverse-', dir=lib.mode_capable()) as tmp:
    tmp = Path(tmp)
    probe = tmp / 'probe'
    subprocess.run(['clang', '-O1', '-static', '-I', str(lib.REPO / 'src/payload/include'),
                    '-I', str(lib.REPO / 'src/payload/arch/aarch64'),
                    str(Path(__file__).with_name('probe.c')), '-o', str(probe)], check=True)
    vol = tmp / 'vol'
    vol.mkdir()
    (vol / 'f').write_text('volume-data\n')

    def run(root, *args):
        p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, '--isolate', '--mode', 'container',
                            '--root', str(root), '-v', f'{vol}:/mnt/vol', '--guard-file-access', 'dw',
                            '--allow-stdio-output', '--', './.elf-exec', *args],
                           capture_output=True, text=True, timeout=60, cwd='/')
        return parse(p.stdout) + (p.stdout + p.stderr,)

    for case in ('hidden', 'hidden-in-mnt', 'skeleton'):
        root = tmp / f'root-{case}'
        (root / 'mnt' / 'vol').mkdir(parents=True)
        shutil.copy2(probe, root / '.elf-exec')
        if case == 'hidden':
            (root / 'hidden-secret').write_text('x')
        if case == 'hidden-in-mnt':
            (root / 'mnt' / 'hidden-secret').write_text('x')
        v, _, out = run(root, 'h', 'stat', '/')
        check(f'{case}: stat / passes through', v.get('stat') == 0, out)
        v, _, out = run(root, 'h', 'chdir', '/mnt')
        check(f'{case}: chdir /mnt passes through', v.get('chdir') == 0, out)
        v, _, out = run(root, 'h', 'open', '/mnt/vol/f', '0')
        check(f'{case}: the volume reads', v.get('open') == 0 and 'volume-data' in out, out)
        for path in ('/', '/mnt'):
            v, names, out = run(root, 'h', 'rawlist', path)
            hidden = case == 'hidden' and path == '/' or case == 'hidden-in-mnt' and path == '/mnt'
            if hidden:
                check(f'{case}: listing {path} from a broker FD is refused', v.get('rawlist') == EACCES and
                      names is None and 'hidden-secret' not in out, out)
                v, _, out = run(root, 'h', 'inotify', path)
                check(f'{case}: inotify on {path} is refused', v.get('inotify') == EACCES, out)
            else:
                shown = {'.elf-exec', 'mnt'} if path == '/' else {'vol'}
                check(f'{case}: listing {path} shows only the view\'s names',
                      v.get('rawlist') == 0 and names is not None and set(names) - {'.', '..'} == shown, out)

if failures:
    print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
    sys.exit(1)
print('traverse acceptance: all passed')
