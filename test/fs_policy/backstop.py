#!/usr/bin/env python3
"""--seccomp-backstop: unhooked syscalls still get guest semantics.

A raw svc written into already-executable code (through /proc/self/mem, so
no hook ever sees it) reaches the host untranslated without the backstop;
with it the seccomp filter traps the call and the payload translates it.
The HarmonyOS kernel exempts writable+executable pages from seccomp, so the
backstop refuses such mappings (W^X). Calls the host sandbox itself traps
keep their native effect. Both builds."""
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: rootfs unavailable:', alpine)
    raise SystemExit(0)
release = (alpine / 'etc/alpine-release').read_text().strip()
with tempfile.TemporaryDirectory(prefix='backstop-', dir=build) as tmp:
    work = Path(tmp)
    subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-Wl,-e,_start',
                    str(repo / 'test/fs_policy/backstop_probe.c'), '-o', str(work / 'probe')],
                   check=True)
    for suffix in ('', '-fd-experiment'):
        loader = build / f'elfloader-proot{suffix}'
        manifest = json.loads((build / f'elf-build{suffix}.json').read_text())
        assert hashlib.sha256(loader.read_bytes()).hexdigest() == manifest['sha256']
        def run(options, mode):
            p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine), *options,
                                '-v', '/proc:/proc', '-v', f'{work}:/work', '--', './bin/busybox',
                                'sh', '-c', f'/work/probe {mode}; /bin/busybox echo after=$?'],
                               cwd=alpine, capture_output=True, text=True, timeout=60)
            assert p.returncode == 0, (suffix, options, mode, p.stdout, p.stderr[-1500:])
            return p.stdout.split('\n')[:2]
        # Without the backstop the injected call misses the guest file.
        plain = run([], 'm')
        assert plain[0] != f'open={release}' and plain[1] == 'after=0', (suffix, plain)
        assert run([], 'x') == ['rwx=0', 'after=0'], suffix
        # With it the call is trapped and translated; exec children keep it.
        assert run(['--seccomp-backstop'], 'm') == [f'open={release}', 'after=0'], suffix
        assert run(['--seccomp-backstop'], 'x') == ['rwx=-13', 'after=0'], suffix
        print('PASS: seccomp backstop translates unhooked syscalls and refuses RWX:', loader.name)
