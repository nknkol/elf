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
    assert printed['enforcement'] == 'isolate-broker' and '--isolate' in printed['argv'], printed
    assert '--guard-file-access' in printed['argv'] and not state.exists(), printed
    p = run(*common, '--backend', 'in-process', '--print', '--', '/bin/sh', '-c', 'true')
    printed = json.loads(p.stdout)
    assert printed['enforcement'] == 'experimental-file-access-guard' and '--isolate' not in printed['argv'], printed
    print('PASS: dry run prints the enforced launch (broker by default) without creating state')

    env = dict(os.environ, ELF_SENTINEL_SECRET='host-only')
    p = run(*common, '--backend', 'in-process', '--', '/bin/sh', '-c', SCRIPT, env=env)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    inproc = p.stdout
    for leftover in (workspace / 'made', state / 'home/h', state / 'tmp/t'):
        leftover.unlink()
    p = run(*common, '--', '/bin/sh', '-c', SCRIPT, env=env)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    assert p.stdout == inproc, ('the broker backend shows a different view', inproc, p.stdout)
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
    print('PASS: guest shell runs with clean env, private state, filtered root and policy '
          '(broker backend, same view as in-process)')

    # Private state persists; the skeleton root is rebuilt on each launch.
    p = run(*common, '--', '/bin/sh', '-c', 'cat "$HOME/h"')
    assert (p.returncode, p.stdout) == (0, 'h\n'), (p.stdout, p.stderr)
    p = run(*common, '--', '/bin/missing')
    assert p.returncode == 127 and 'exec failed' in p.stderr, (p.returncode, p.stderr)
    print('PASS: persistent private state and guest exec errors')

    # FDs the caller left open (a file outside the profile, a writable one,
    # a directory, a UNIX socket) do not reach the guest; stdio and an
    # explicit --pass-fd (here a pipe the guest reads) do.
    outside = base / 'outside'
    outside.mkdir()
    (outside / 'secret').write_text('LEFT-OPEN-SECRET\n')
    (outside / 'target').write_text('unchanged\n')
    a, b = __import__('socket').socketpair()
    r_secret = os.open(outside / 'secret', os.O_RDONLY)
    w_target = os.open(outside / 'target', os.O_WRONLY | os.O_APPEND)
    d_outside = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
    for backend in ('isolate', 'in-process'):
        granted_r, granted_w = os.pipe()
        os.write(granted_w, b'granted\n')
        os.close(granted_w)
        fds = {'r': r_secret, 'w': w_target, 'd': d_outside, 's': a.fileno(), 'g': granted_r}
        # (true, not ":": a failed redirection of a special built-in ends the shell)
        probe = '; '.join(f'true <&{n} 2>/dev/null && echo open-{k} || echo closed-{k}' for k, n in fds.items())
        probe += (f'; cat <&{r_secret} 2>/dev/null; echo leaked 2>/dev/null >&{w_target}; '
                  f'cat <&{granted_r}')
        p = subprocess.run(['python3', str(launch), *common, '--backend', backend, '--pass-fd', str(granted_r),
                            '--', '/bin/sh', '-c', probe], capture_output=True, text=True, timeout=60,
                           pass_fds=list(fds.values()))
        os.close(granted_r)
        lines = p.stdout.split()
        assert all(f'closed-{k}' in lines for k in 'rwds') and 'open-g' in lines, (backend, p.stdout, p.stderr)
        assert 'LEFT-OPEN-SECRET' not in p.stdout and (outside / 'target').read_text() == 'unchanged\n', \
            (backend, p.stdout)
        assert 'granted' in lines, (backend, p.stdout, p.stderr)
    for fd in (r_secret, w_target, d_outside):
        os.close(fd)
    a.close()
    b.close()
    print('PASS: FDs the caller left open do not reach the guest; stdio and --pass-fd do')

    # Writable FDs given with --pass-fd stay writable under both backends:
    # a pipe write end (written by a builtin and, through stdout, by an
    # executed program) and a file outside every mount opened for append.
    # The same file opened read-only and passed is not writable.
    for backend in ('isolate', 'in-process'):
        out_r, out_w = os.pipe()
        log = outside / f'passed-{backend}.log'
        log.write_text('start\n')
        appender = os.open(log, os.O_WRONLY | os.O_APPEND)
        reader = os.open(log, os.O_RDONLY)
        script = (f'echo builtin-{backend} >&{out_w}; printf "exec-{backend}\\n" | cat >&{out_w}; '
                  f'echo appended >&{appender}; '
                  f'echo refused 2>/dev/null >&{reader} && echo read-only-written || echo read-only-refused')
        p = subprocess.run(['python3', str(launch), *common, '--backend', backend, '--pass-fd', str(out_w),
                            '--pass-fd', str(appender), '--pass-fd', str(reader), '--pass-fd', str(out_w),
                            '--', '/bin/sh', '-c', script],
                           capture_output=True, text=True, timeout=60, pass_fds=[out_w, appender, reader])
        for fd in (out_w, appender, reader):
            os.close(fd)
        with os.fdopen(out_r, 'rb') as f:
            got = f.read()
        assert p.returncode == 0 and got == f'builtin-{backend}\nexec-{backend}\n'.encode(), \
            (backend, p.returncode, got, p.stdout, p.stderr)
        assert log.read_text() == 'start\nappended\n' and 'read-only-refused' in p.stdout, \
            (backend, log.read_text(), p.stdout, p.stderr)
    print('PASS: writable FDs given with --pass-fd stay writable under both backends; a read-only one does not')

    # --pass-fd is checked before anything starts: a negative number, an FD
    # that is not open, and one the runtime holds are refused; repeats and
    # stdio are accepted.
    closed = os.open('/dev/null', os.O_RDONLY)
    os.close(closed)
    for value, why in (('-1', 'not an FD number'), (str(closed), 'not an open FD'),
                       ('898', "runtime's own"), ('901', "runtime's own")):
        p = run(*common, '--pass-fd', value, '--', '/bin/sh', '-c', 'echo started')
        assert p.returncode == 2 and why in p.stderr and 'started' not in p.stdout, (value, p.returncode, p.stderr)
    p = run(*common, '--pass-fd', '1', '--pass-fd', '1', '--pass-fd', '2', '--print', '--',
            '/bin/sh', '-c', 'true')
    printed = json.loads(p.stdout)['argv']
    assert p.returncode == 0 and printed.count('--pass-fd') == 2, (p.returncode, p.stderr, printed)
    # The loader itself refuses the same (it records the object at start).
    loader_cmd = [str(build / 'elfloader-guarded'), '--mode', 'container', '--root', str(alpine),
                  '--guard-file-mutations', 'w']
    for value, why in ((str(closed), 'not an open FD'), ('899', "runtime's own")):
        p = subprocess.run([*loader_cmd, '--pass-fd', value, '--', '/bin/true'], capture_output=True,
                           text=True, timeout=60)
        assert p.returncode != 0 and why in p.stderr, (value, p.returncode, p.stderr)
    print('PASS: --pass-fd refuses negative, unopened and runtime-reserved FDs before starting; repeats count once')

    many = dict(json.loads(profile.read_text()))
    # 8 mounts used; 57 more exceed the 64-mount backend limit.
    for index in range(57):
        (base / f'extra{index}').mkdir()
        many['mounts'].append({'source': str(base / f'extra{index}'), 'target': f'/x{index}',
                               'access': 'ro'})
    crowded = base / 'many.json'
    crowded.write_text(json.dumps(many))
    foreign = base / 'foreign-state'
    (foreign / 'root').mkdir(parents=True)
    for args, marker in (
            ([str(crowded), *common[1:], '--', '/bin/true'], 'at most 64 mounts'),
            ([*common, '--', 'bin/true'], 'absolute guest path'),
            ([*common[:-1], str(foreign), '--', '/bin/true'], 'not created by this launcher'),
            ([*common[:-1], str(workspace / 'state'), '--', '/bin/true'], 'Private state'),
            ([*common, '--env', 'BROKEN', '--', '/bin/true'], 'KEY=VALUE')):
        p = run(*args)
        assert p.returncode != 0 and marker in p.stderr, (args, p.stderr)
    assert not any((foreign / 'root').iterdir())
    print('PASS: launcher rejects backend limits, relative commands and foreign state')
