#!/usr/bin/env python3
"""--pass-fd keeps an FD's own capability (docs/ISOLATION.md; part of the
application sandbox's acceptance suite): what the FD's access mode allows,
outside the path policy, the same through the payload as by a direct call.

The loader (guarded build, with and without --isolate) gets three FDs on
objects outside every mount: a file opened for append, a file opened
read-only and a directory, each with --pass-fd, plus a fourth writable FD
it merely inherits. The probe writes, reads, lists and chmods each FD once
through the payload (h) and once by a direct call (d).

Expected: on a passed FD, the write, read and listing give the same result
both ways, which is the kernel's for that access mode (no upgrade: the
read-only FD is not writable, the append FD not readable); a chmod is
refused through the payload, and under --isolate by a direct call too (the
guest filter refuses FD metadata calls). The merely inherited FD is not
writable through the payload. The host sees exactly the writes made."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

EBADF, EACCES, EISDIR = -9, -13, -21
failures = []
loader = lib.BUILD / 'elfloader-guarded'
if not loader.exists():
    print('SKIP: elfloader-guarded missing')
    sys.exit(0)


def check(tag, ok, detail=''):
    print('PASS:' if ok else 'FAIL:', tag, '' if ok else detail)
    if not ok:
        failures.append(tag)


with tempfile.TemporaryDirectory(prefix='iso-passfd-', dir=lib.mode_capable()) as tmp:
    tmp = Path(tmp)
    root = tmp / 'root'
    root.mkdir()
    probe = root / '.elf-exec'
    subprocess.run(['clang', '-O1', '-static', '-I', str(lib.REPO / 'src/payload/include'),
                    '-I', str(lib.REPO / 'src/payload/arch/aarch64'),
                    str(Path(__file__).with_name('probe.c')), '-o', str(probe)], check=True)
    out = tmp / 'outside'
    (out / 'dir').mkdir(parents=True)
    (out / 'dir' / 'entry').write_text('e\n')
    (out / 'read.txt').write_text('readable\n')
    for backend in ('isolate', 'in-process'):
        log, other = out / f'append-{backend}.log', out / f'inherited-{backend}.log'
        log.write_text('')
        other.write_text('')
        fds = {'append': os.open(log, os.O_WRONLY | os.O_APPEND),
               'read-only': os.open(out / 'read.txt', os.O_RDONLY),
               'directory': os.open(out / 'dir', os.O_RDONLY | os.O_DIRECTORY),
               'inherited': os.open(other, os.O_WRONLY | os.O_APPEND)}
        modes = os.stat(log).st_mode, os.stat(out / 'read.txt').st_mode, os.stat(out / 'dir').st_mode
        passed = [x for k in ('append', 'read-only', 'directory') for x in ('--pass-fd', str(fds[k]))]
        results = {}
        for kind, fd in fds.items():
            for how in ('h', 'd'):
                p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, *(['--isolate'] if backend == 'isolate' else []),
                                    '--mode', 'container', '--root', str(root), '--guard-file-access', 'd',
                                    '--allow-stdio-output', *passed, '--', './.elf-exec', how, 'fdcalls', str(fd)],
                                   capture_output=True, text=True, timeout=60, cwd='/', pass_fds=list(fds.values()))
                got = dict(line.split() for line in p.stdout.splitlines() if line.startswith('fd-'))
                results[(kind, how)] = {k: int(v) for k, v in got.items()} or p.stdout + p.stderr
        for fd in fds.values():
            os.close(fd)
        tag = f' ({backend})'
        ok = all(isinstance(r, dict) for r in results.values())
        check('every probe ran' + tag, ok, results)
        if not ok:
            continue
        expect = {'append': {'fd-write': 1, 'fd-read': EBADF, 'fd-list': 0},
                  'read-only': {'fd-write': EBADF, 'fd-read': 9, 'fd-list': 0},
                  'directory': {'fd-write': EBADF, 'fd-read': EISDIR, 'fd-list': 1}}
        for kind, want in expect.items():
            h, d = results[(kind, 'h')], results[(kind, 'd')]
            same = {k: h[k] for k in want} == want and {k: d[k] for k in want} == want
            check(f'a passed {kind} FD: write, read and listing as its access mode allows, '
                  f'the same through the payload and directly' + tag, same, [h, d])
            refused = h['fd-chmod'] < 0 and (backend != 'isolate' or d['fd-chmod'] < 0)
            check(f'a passed {kind} FD: chmod refused (a metadata change is no FD capability)' + tag,
                  refused, [h, d])
        check('an inherited FD not passed is not writable through the payload' + tag,
              results[('inherited', 'h')]['fd-write'] == EACCES, results[('inherited', 'h')])
        after = os.stat(log).st_mode, os.stat(out / 'read.txt').st_mode, os.stat(out / 'dir').st_mode
        check('host: the append file holds exactly the two writes; nothing read-only changed; modes kept' + tag,
              log.read_text() == 'xx' and (out / 'read.txt').read_text() == 'readable\n' and after == modes,
              [log.read_text(), (out / 'read.txt').read_text(), after, modes])

if failures:
    print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
    sys.exit(1)
print('pass-fd acceptance: all passed')
