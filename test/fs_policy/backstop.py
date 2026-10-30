#!/usr/bin/env python3
"""--seccomp-backstop: unhooked syscalls still get guest semantics.

A raw svc written into already-executable code (through /proc/self/mem, so
no hook ever sees it) reaches the host untranslated without the backstop;
with it the seccomp filter traps the call and the payload translates it.
Writable+executable memory is allowed: HongMeng runs no syscall issued from
anonymous RWX pages, so code written there cannot reach the host either
way. Calls the host sandbox itself traps keep their native effect. Both
builds."""
import hashlib
import json
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
    print('SKIP: rootfs unavailable:', alpine)
    raise SystemExit(0)
release = (alpine / 'etc/alpine-release').read_text().strip()
with tempfile.TemporaryDirectory(prefix='backstop-', dir=build) as tmp:
    work = Path(tmp)
    subprocess.run([*lib.PROBE, str(repo / 'test/fs_policy/backstop_probe.c'), '-o', str(work / 'probe')],
                   check=True)
    # One RWX segment (--omagic): refused at load time under the backstop.
    subprocess.run([*lib.PROBE, '-Wl,--omagic',
                    str(repo / 'test/fs_policy/backstop_probe.c'), '-o', str(work / 'probe-wx')],
                   check=True)
    for suffix in ('', '-guarded'):
        loader = lib.loader(suffix)
        def run(options, mode):
            # mode x opens a host-only path (not in the guest view) from RWX memory.
            p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine), *options,
                                '-v', '/proc:/proc', '-v', f'{work}:/work', '--', './bin/busybox',
                                'sh', '-c', f'/work/probe {mode} {alpine}/etc/alpine-release; '
                                '/bin/busybox echo after=$?'],
                               cwd=alpine, capture_output=True, text=True, timeout=60)
            assert p.returncode == 0, (suffix, options, mode, p.stdout, p.stderr[-1500:])
            return p.stdout.split('\n')[:-1]
        # Without the backstop the injected call misses the guest file.
        plain = run([], 'm')
        assert plain[0] != f'open={release}' and plain[1] == 'after=0', (suffix, plain)
        # RWX memory: the mapping works, its syscalls never run (ENOENT).
        assert run([], 'x') == ['rwx=0', 'open=-2', 'after=0'], suffix
        # x8 high bits: the kernel performs openat, so the payload must too.
        assert run([], 'w') == [f'open={release}', 'after=0'], suffix
        # With it the call is trapped and translated; exec children keep it.
        assert run(['--seccomp-backstop'], 'm') == [f'open={release}', 'after=0'], suffix
        assert run(['--seccomp-backstop'], 'x') == ['rwx=0', 'open=-2', 'after=0'], suffix
        def run_wx(options):
            p = subprocess.run([str(loader), '--mode', 'container', '--root', str(alpine), *options,
                                '-v', f'{work}:/work', '--', './bin/busybox', 'sh', '-c',
                                f'/work/probe-wx x {alpine}/etc/alpine-release; /bin/busybox echo after=$?'],
                               cwd=alpine, capture_output=True, text=True, timeout=60)
            return p.stdout.split('\n')[:-1]
        # A program with one RWX segment (--omagic) runs under both.
        for options in ([], ['--seccomp-backstop']):
            assert run_wx(options) == ['rwx=0', 'open=-2', 'after=0'], (suffix, options)
        print('PASS: seccomp backstop translates unhooked syscalls; RWX code never reaches the host:',
              loader.name)
