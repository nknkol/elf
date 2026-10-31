#!/usr/bin/env python3
"""Executable memory as JITs use it, under both builds: anonymous RW->RX,
RWX, patching RX code; a shared executable mapping of a memfd is refused
(EACCES, as HarmonyOS refuses it natively) instead of becoming a stale copy;
a private executable mapping of a file still runs."""
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

expected = {'rw-rx': '42', 'rwx': '42', 'patched': '123', 'memfd-shared-exec': '-13', 'file-private-exec': '42'}
with tempfile.TemporaryDirectory(prefix='jit-', dir=lib.BUILD) as temp:
    work = Path(temp)
    probe = work / 'jit_probe'
    subprocess.run(['clang', '-O1', '-static', str(Path(__file__).with_name('jit_probe.c')), '-o', str(probe)],
                   check=True)
    failures = []
    for suffix, loader in lib.loaders():
        p = subprocess.run([str(loader), *lib.EXTRA, '--mode', 'compat', '--', str(probe)], cwd=work,
                           capture_output=True, text=True, timeout=60, env={'JIT_DIR': str(work), 'PATH': '/usr/bin:/bin'})
        got = dict(line.split(' ', 1) for line in p.stdout.splitlines() if ' ' in line)
        bad = {k: got.get(k) for k, v in expected.items() if got.get(k) != v}
        print('FAIL:' if bad else 'PASS:', f'{loader.name}: executable memory', bad or '')
        if bad:
            failures.append(f'{loader.name}: {bad} {p.stdout[-300:]!r} {p.stderr[-300:]!r}')
    if failures:
        sys.exit('\n'.join(failures))
