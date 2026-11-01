#!/usr/bin/env python3
"""A denied root under --isolate (docs/ISOLATION.md, "拒绝根上的经过与列目录";
part of the application sandbox's acceptance suite).

The root is denied ('d'), a volume is mounted at /mnt/vol. The broker lets
the guest pass through /, /mnt (stat, chdir) to reach the volume. The
names of such a directory are never read from it: the probe opens it
through the payload (the broker answers) and lists the FD from the
payload's own svc, skipping the payload's filter.

Expected, guarded build with --isolate, for a root with a hidden file, one
with a hidden file in /mnt, and a skeleton root:
  - stat of / and chdir to /mnt succeed, the volume's file reads;
  - listing / shows exactly ".elf-exec" and "mnt", listing /mnt exactly
    "vol": never a hidden name;
  - a name the host adds while the guest holds the FD does not show up
    when the guest lists that FD afterwards;
  - an inotify watch on them is refused (EACCES);
  - a real directory held as O_PATH and opened again through its magic
    link (through the payload, and by a forged broker request) gives the
    synthesized copy or nothing, never the real names."""
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
            shown = {'.elf-exec', 'mnt'} if path == '/' else {'vol'}
            v, names, out = run(root, 'h', 'rawlist', path)
            check(f'{case}: listing {path} from a broker FD shows only the view\'s names',
                  v.get('rawlist') == 0 and names is not None and set(names) - {'.', '..'} == shown, out)
            v, _, out = run(root, 'h', 'inotify', path)
            check(f'{case}: inotify on {path} is refused', v.get('inotify') == EACCES, out)
        # A real directory held as O_PATH (passing through), opened again by
        # its magic link, through the payload and by a forged request.
        for path in ('/', '/mnt'):
            shown = {'.elf-exec', 'mnt'} if path == '/' else {'vol'}
            p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, '--isolate', '--mode', 'container',
                                '--root', str(root), '-v', f'{vol}:/mnt/vol', '--guard-file-access', 'dw',
                                '--allow-stdio-output', '--', './.elf-exec', 'h', 'reopen', path],
                               capture_output=True, text=True, timeout=60, cwd='/')
            out = p.stdout + p.stderr
            values = {}
            listed = {}
            for line in p.stdout.splitlines():
                key, sep, rest = line.partition('-names=')
                if sep:
                    listed[key] = {n for n in rest.split(',') if n} - {'.', '..'}
                elif ' ' in line:
                    k, _, v = line.rpartition(' ')
                    values[k] = int(v) if v.lstrip('-').isdigit() else v
            for how in ('reopen-proc', 'reopen-forged'):
                ok = values.get('held') == 0 and how in values and (
                    (values[how] == 0 and listed.get(how) == shown) or
                    (values[how] != 0 and how not in listed))
                check(f'{case}: {path} held as O_PATH, {how}: only the view\'s names or refused',
                      ok and 'hidden-secret' not in out, out)
        # A name added while the guest holds the FD.
        p = subprocess.Popen([str(loader), *lib.ISOLATE_EXTRA, '--isolate', '--mode', 'container',
                              '--root', str(root), '-v', f'{vol}:/mnt/vol', '--guard-file-access', 'dw',
                              '--allow-stdio-output', '--allow-stream-input', '--', './.elf-exec', 'h',
                              'rawlistwait', '/'],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             cwd='/')
        first = p.stdout.readline()
        (root / 'added-later').write_text('x')
        out, err = p.communicate('go\n', timeout=60)
        (root / 'added-later').unlink()
        _, names = parse(first + out)
        check(f'{case}: a name added later does not show in the held FD',
              first.strip() == 'rawlist 0' and names is not None and 'added-later' not in names and
              set(names) - {'.', '..'} == {'.elf-exec', 'mnt'}, first + out + err)

if failures:
    print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
    sys.exit(1)
print('traverse acceptance: all passed')
