#!/usr/bin/env python3
"""Agent profile launch: real guest shell under the generated file access policy."""
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
launch = repo / 'tools/agent_sandbox/launch.py'
alpine = build / 'alpine-test-root'
if not (alpine / 'bin/busybox').exists():
    print('SKIP: agent launch rootfs unavailable:', alpine)
    raise SystemExit(0)

SCRIPT = '''pwd
echo "HOME=$HOME TMPDIR=$TMPDIR"
echo "sentinel=$(env | grep -c SENTINEL)"
cat note
echo made > made
echo h > "$HOME/h"
echo t > "$TMPDIR/t"
ls -a / | tr '\\n' ' '; echo
tool
cat /etc/passwd 2>/dev/null || echo no-etc
echo x 2>/dev/null > /bin/x || echo ro-bin
cat /.elf-skeleton 2>/dev/null || echo hidden-marker
printf piped | cat
echo
'''


def run(*args, env=None):
    return subprocess.run(['python3', str(launch), *args], capture_output=True, text=True,
                          timeout=60, env=env)


with tempfile.TemporaryDirectory(prefix='agent-launch-', dir=build) as tmp:
    base = Path(tmp)
    brew, workspace, state = base / 'brew', base / 'workspace', base / 'state'
    (brew / 'bin').mkdir(parents=True)
    workspace.mkdir()
    (workspace / 'note').write_text('workspace-note\n')
    tool = brew / 'bin/tool'
    tool.write_text('#!/bin/sh\necho brew-tool\n')
    tool.chmod(0o755)
    profile = base / 'profile.json'
    mounts = [{'source': str(alpine / name), 'target': f'/{name}', 'access': 'ro'}
              for name in ('bin', 'lib', 'usr')]
    mounts += [{'source': '${BREW_PREFIX}', 'access': 'ro'},
               {'source': '${WORKSPACE}', 'target': '/workspace', 'access': 'rw'},
               {'source': '/dev/null', 'access': 'rw'}]
    profile.write_text(json.dumps({'version': 1, 'default': 'deny', 'mounts': mounts,
                                   'private': [{'name': 'home', 'target': '/home/agent'},
                                               {'name': 'tmp', 'target': '/tmp'}]}))
    common = [str(profile), '--brew-prefix', str(brew), '--workspace', str(workspace),
              '--state', str(state)]

    p = run(*common, '--print', '--', '/bin/sh', '-c', 'true')
    assert p.returncode == 0, p.stderr
    printed = json.loads(p.stdout)
    assert printed['enforcement'] == 'experimental-file-access-guard', printed
    assert '--guard-file-access' in printed['argv'] and not state.exists(), printed
    print('PASS: dry run prints the enforced launch without creating state')

    env = dict(os.environ, ELF_SENTINEL_SECRET='host-only')
    p = run(*common, '--', '/bin/sh', '-c', SCRIPT, env=env)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    lines = p.stdout.splitlines()
    assert lines[0] == '/workspace', p.stdout
    assert 'HOME=/home/agent TMPDIR=/tmp' in lines and 'sentinel=0' in lines, p.stdout
    assert 'workspace-note' in lines and 'brew-tool' in lines, p.stdout
    for marker in ('no-etc', 'ro-bin', 'hidden-marker', 'piped'):
        assert marker in lines, (marker, p.stdout)
    listing = set(next(line for line in lines if ' bin ' in f' {line} ').split())
    top = str(brew).split('/')[1]
    assert listing == {'.', '..', 'bin', 'lib', 'usr', 'dev', 'home', 'tmp', 'workspace', top}, listing
    assert (workspace / 'made').read_text() == 'made\n'
    assert (state / 'home/h').read_text() == 'h\n' and (state / 'tmp/t').read_text() == 't\n'
    assert not (alpine / 'bin/x').exists()
    print('PASS: guest shell runs with clean env, private state, filtered root and policy')

    # Private state persists; the skeleton root is rebuilt on each launch.
    p = run(*common, '--', '/bin/sh', '-c', 'cat "$HOME/h"')
    assert (p.returncode, p.stdout) == (0, 'h\n'), (p.stdout, p.stderr)
    p = run(*common, '--', '/bin/missing')
    assert p.returncode == 127 and 'exec failed' in p.stderr, (p.returncode, p.stderr)
    print('PASS: persistent private state and guest exec errors')

    many = dict(json.loads(profile.read_text()))
    # 8 mounts used; nine more exceed the 16-mount backend limit.
    for index in range(9):
        (base / f'extra{index}').mkdir()
        many['mounts'].append({'source': str(base / f'extra{index}'), 'target': f'/x{index}',
                               'access': 'ro'})
    crowded = base / 'many.json'
    crowded.write_text(json.dumps(many))
    foreign = base / 'foreign-state'
    (foreign / 'root').mkdir(parents=True)
    for args, marker in (
            ([str(crowded), *common[1:], '--', '/bin/true'], 'at most 16 mounts'),
            ([*common, '--', 'bin/true'], 'absolute guest path'),
            ([*common[:-1], str(foreign), '--', '/bin/true'], 'not created by this launcher'),
            ([*common[:-1], str(workspace / 'state'), '--', '/bin/true'], 'Private state'),
            ([*common, '--env', 'BROKEN', '--', '/bin/true'], 'KEY=VALUE')):
        p = run(*args)
        assert p.returncode != 0 and marker in p.stderr, (args, p.stderr)
    assert not any((foreign / 'root').iterdir())
    print('PASS: launcher rejects backend limits, relative commands and foreign state')
