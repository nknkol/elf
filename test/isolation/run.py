#!/usr/bin/env python3
"""Isolation acceptance (docs/ISOLATION_TESTING.md), goals A-L.

Host layout (on a backing that accepts socket files):
  outside/  not in any tree: secret, prog, a listening socket
  ro/       bound at /ro, read-only in the guarded build
  hidden/   bound at /hidden, invisible in the guarded build
  rw/       bound at /rw, writable
The guest is ./iso-probe (test/isolation/probe.c) in the Alpine root. Every
operation runs through the payload ("h") and from the payload's own svc
("d"). outside/, ro/ and hidden/ are hashed with their metadata before and
after; no output may contain a secret. Both builds; the plain build has
only writable trees, so goals B, C, K and the read-only parts of D, E, I, L
run in the guarded build."""
import hashlib
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

alpine = lib.require(lib.ALPINE / 'bin/busybox').parents[1]
EPERM = -1
failures = []


def socket_capable():
    for base in (lib.BUILD, Path(tempfile.gettempdir()), Path('/data/storage/el2/base/cache')):
        try:
            with tempfile.TemporaryDirectory(prefix='sock-probe-', dir=base) as tmp:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.bind(str(Path(tmp) / 's'))
            return base
        except OSError:
            continue
    raise SystemExit('no backing directory accepts UNIX socket files')


def snapshot(*roots):
    """Content hash and metadata of every entry (sockets excluded)."""
    state = {}
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            for name in [*dirnames, *filenames]:
                path = Path(dirpath) / name
                st = path.lstat()
                if path.is_socket():
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else ''
                state[str(path)] = (digest, st.st_mode, st.st_uid, st.st_gid, st.st_size, st.st_mtime_ns,
                                    st.st_ctime_ns, st.st_ino, st.st_nlink)
    return state


def parse(output):
    values = {}
    for line in output.splitlines():
        parts = line.split(' ', 1)
        if len(parts) == 2:
            try:
                values[parts[0]] = int(parts[1])
            except ValueError:
                values[parts[0]] = parts[1]
    return values


neg = lambda v: isinstance(v, int) and v < 0          # noqa: E731
eperm = lambda v: v == EPERM or (isinstance(v, int) and v <= -1000)  # EPERM, or killed by the host sandbox  # noqa: E731
zero = lambda v: v == 0                                # noqa: E731

with tempfile.TemporaryDirectory(prefix='iso-accept-', dir=socket_capable()) as tmp:
    base = Path(tmp)
    binary = base / 'iso-probe'
    subprocess.run(['clang', '-O1', '-static', '-I', str(lib.REPO / 'src/payload/include'),
                    '-I', str(lib.REPO / 'src/payload/arch/aarch64'),
                    str(Path(__file__).with_name('probe.c')), '-o', str(binary)], check=True)
    secret = {k: f'{k.upper()}-SECRET-{secrets.token_hex(8)}' for k in ('outside', 'ro', 'hidden')}
    for name in ('outside', 'ro', 'hidden', 'rw'):
        (base / name).mkdir()
    for name in ('outside', 'ro', 'hidden'):
        (base / name / 'secret').write_text(secret[name] + '\n')
        shutil.copy2(binary, base / name / 'prog')
    (base / 'ro/sub').mkdir()
    (base / 'ro/file').write_text(secret['ro'] + '\n')
    (base / 'rw/file').write_text('rw-data\n')
    (base / 'rw/scratch').write_text('scratch\n')
    # Escapes tried from the writable tree.
    (base / 'rw/abs-link').symlink_to(base / 'outside/secret')
    (base / 'rw/rel-link').symlink_to('../../outside/secret')
    (base / 'rw/ro-link').symlink_to('/ro/file')
    # Directory links: one to a host directory outside every tree, one
    # inside the tree (relative, like Ubuntu's /bin -> usr/bin).
    (base / 'rw/out-dir').symlink_to(base / 'outside')
    (base / 'rw/sub').mkdir()
    (base / 'rw/sub/inner').write_text('inner-data\n')
    (base / 'rw/in-dir').symlink_to('sub')
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(base / 'outside/sock'))
    listener.listen(8)
    shutil.copy2(binary, alpine / 'iso-probe')
    before = snapshot(base / 'outside', base / 'ro', base / 'hidden')
    H = {k: str(base / k) for k in ('outside', 'ro', 'hidden', 'rw')}

    try:
        for suffix, loader in lib.loaders():
            guarded = suffix == '-guarded'
            volumes = [(base / 'ro', '/ro'), (base / 'hidden', '/hidden'), (base / 'rw', '/rw'),
                       ('/dev/null', '/dev/null'), ('/proc', '/proc')]
            policy = ['--guard-file-access', 'wrdwwr', '--allow-stdio-output', '--allow-stream-input'] if guarded else []

            def run(*args, isolate=True, shell=False, control=False):
                argv = [str(loader), *(['--isolate'] if isolate else []), '--mode', 'container',
                        '--root', str(alpine)]
                for host, guest in volumes:
                    argv += ['-v', f'{host}:{guest}']
                command = ['./bin/busybox', 'sh', '-c', '/iso-probe ' + ' '.join(args)] if shell \
                    else ['./iso-probe', *args]
                p = subprocess.run([*argv, *policy, '--', *command], cwd=alpine, capture_output=True,
                                   text=True, timeout=120, stdin=subprocess.DEVNULL)
                for name, value in secret.items():
                    if not control and name != 'ro' and value in p.stdout + p.stderr:
                        failures.append(f'{loader.name}: {args}: {name} secret leaked')
                return p, parse(p.stdout)

            def expect(goal, args, checks, **kw):
                p, values = run(*args, **kw)
                bad = [f'{label}={values.get(label)!r}' for label, ok in checks.items() if not ok(values.get(label))]
                tag = f'{goal} {loader.name} {" ".join(args)}'
                if bad:
                    failures.append(f'{tag}: {", ".join(bad)}; out={p.stdout.strip()[-300:]!r} err={p.stderr.strip()[-300:]!r}')
                    print('FAIL:', tag, bad)
                else:
                    print('PASS:', tag)
                return p, values

            # The probe really bypasses the payload: without isolation the direct
            # call reaches the host file (so the refusals below mean something).
            p, values = run('d', 'open', f'{H["outside"]}/secret', '0', isolate=False, control=True)
            if values.get('open') != 0:
                failures.append(f'control {loader.name}: direct open without --isolate gave {values}')
            print('PASS:' if values.get('open') == 0 else 'FAIL:', 'control: direct call reaches the host without --isolate', loader.name)

            # A: outside every tree.
            o = H['outside']
            for op in ('stat', 'lstat', 'statx', 'readlink', 'access', 'statfs', 'chdir', 'getxattr',
                       'listxattr', 'inotify'):
                expect('A', ('d', op, f'{o}/secret'), {op: eperm})
            expect('A', ('d', 'open', f'{o}/secret', '0'), {'open': eperm})
            expect('A', ('d', 'list', o), {'list': eperm})
            expect('A', ('d', 'exec', f'{o}/prog'), {'exec': eperm})
            for op, path in (('open', '/rw/abs-link'), ('open', '/rw/rel-link')):
                expect('A', ('h', op, path, '0'), {op: neg})
            expect('A', ('h', 'open', f'{o}/secret', '0'), {'open': neg})
            expect('A', ('h', 'open', '/proc/self/root' + f'{o}/secret', '0'), {'open': neg})
            # B: hidden tree.
            if guarded:
                for op in ('stat', 'readlink', 'access', 'chdir', 'getxattr'):
                    expect('B', ('h', op, '/hidden/secret'), {op: neg})
                expect('B', ('h', 'open', '/hidden/secret', '0'), {'open': neg})
                expect('B', ('h', 'list', '/hidden'), {'list': neg})
                expect('B', ('d', 'open', f'{H["hidden"]}/secret', '0'), {'open': eperm})
            # C: read-only tree.
            if guarded:
                expect('C', ('h', 'open', '/ro/file', '0'), {'open': zero})
                expect('C', ('h', 'list', '/ro'), {'list': zero})
                for flags in ('1', '2', '1001', '100', '20200002'):
                    path = '/ro/new' if flags in ('100', '20200002') else '/ro/file'
                    expect('C', ('h', 'open', path, flags), {'open': neg})
                for op in ('unlink', 'chmod', 'chown', 'utime', 'truncate', 'setxattr', 'removexattr'):
                    expect('C', ('h', op, '/ro/file'), {op: neg})
                for op in ('mkdir', 'mknod'):
                    expect('C', ('h', op, '/ro/new'), {op: neg})
                expect('C', ('h', 'rmdir', '/ro/sub'), {'rmdir': neg})
                expect('C', ('h', 'symlink', 'x', '/ro/l'), {'symlink': neg})
                expect('C', ('h', 'rename', '/ro/file', '/rw/moved'), {'rename': neg})
                expect('C', ('h', 'rename', '/rw/scratch', '/ro/scratch'), {'rename': neg})
                expect('C', ('h', 'bind', '/ro/sock'), {'bind': neg})
                for op in ('unlink', 'chmod', 'truncate', 'setxattr'):
                    expect('C', ('d', op, f'{H["ro"]}/file'), {op: eperm})
                expect('C', ('d', 'open', f'{H["ro"]}/file', '1001'), {'open': eperm})
            # D: across trees.
            if guarded:
                expect('D', ('h', 'link', '/ro/file', '/rw/hard'), {'link': neg})
                expect('D', ('h', 'open', '/rw/ro-link', '1001'), {'open': neg})
                expect('D', ('h', 'link', '/hidden/secret', '/rw/hard2'), {'link': neg})
                expect('D', ('h', 'rename', '/hidden/secret', '/rw/stolen'), {'rename': neg})
            expect('D', ('h', 'open', '/rw/out-dir/secret', '0'), {'open': neg})
            expect('D', ('h', 'open', '/rw/in-dir/inner', '0'), {'open': zero})
            expect('D', ('h', 'stat', '/rw/in-dir/inner'), {'stat': zero})
            expect('D', ('h', 'symlink', f'{o}/secret', '/rw/made-link'), {'symlink': zero})
            expect('D', ('h', 'open', '/rw/made-link', '0'), {'open': neg})
            # E: tampering with the payload configuration.
            target = '/ro/file' if guarded else '/rw/scratch'
            p, v = expect('E', ('h', 'tamper', f'{o}/secret', '/rw/file', target),
                          {'config-found': lambda x: x == 1, 't-open-host': neg,
                           't-noisolate-host': eperm, 't-noisolate-ro': eperm,
                           **({'t-write-ro': neg, 't-unlink-ro': neg} if guarded else {})})
            # F: the guest filter table and its conditional rules.
            p, v = run('d', 'filter')
            table = {k: x for k, x in v.items() if k.startswith('nr')}
            bad = {k: x for k, x in table.items() if not eperm(x)}
            rules = {'execveat-path': eperm, 'execveat-empty': lambda x: x not in (None, EPERM),
                     'socket-unix': eperm, 'socket-inet': lambda x: x == 1,
                     'socketpair-dgram': eperm, 'socketpair-stream': zero, 'prlimit-self': zero,
                     'prlimit-other': eperm, 'ioctl-setflags': eperm, 'getpid-ok': lambda x: x == 1,
                     'nr-high-bits': eperm}
            bad.update({k: v.get(k) for k, ok in rules.items() if not ok(v.get(k))})
            if bad or len(table) < 70:
                failures.append(f'F {loader.name}: {bad} ({len(table)} numbers)')
            print('FAIL:' if bad else 'PASS:', f'F {loader.name}: {len(table)} refused numbers, rules', bad or '')
            # Through a shell (exec chain): the filter is inherited.
            p, v = run('d', 'open', f'{o}/secret', '0', shell=True)
            ok = v.get('open') == EPERM
            print('PASS:' if ok else 'FAIL:', 'F filter inherited across exec', loader.name)
            ok or failures.append(f'F exec {loader.name}: {v}')
            # G: other processes.
            expect('G', ('h', 'procs'), {'proc-other-status': neg, 'proc-other-mem': neg,
                                         'proc-self-status': zero, 'proc-1-environ': neg,
                                         'vm-readv': eperm, 'vm-writev': eperm, 'vm-readv-hooked': neg,
                                         'ptrace': eperm, 'pidfd-getfd': neg,
                                         'seccomp': lambda x: x == 2})
            # H: fail closed without the broker: the payload's channels closed
            # from its svc, and the broker processes killed from outside.
            expect('H', ('h', 'cutoff', '/rw/file'), {'before': zero, 'close-control': zero,
                                                       'after': neg, 'after-stat': neg, 'after-child': neg})
            argv = [str(loader), '--isolate', '--mode', 'container', '--root', str(alpine),
                    *sum((['-v', f'{h}:{g}'] for h, g in volumes), []), *policy, '--',
                    './iso-probe', 'h', 'killbroker', '/rw/file']
            guest_process = subprocess.Popen(argv, cwd=alpine, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True, start_new_session=True)
            lines = []
            while (line := guest_process.stdout.readline()) and line.strip() != 'ready':
                lines.append(line)
            # The broker and its handlers were forked from the guest before
            # its program started: same process group, other processes.
            killed = 0
            for entry in Path('/proc').iterdir():
                if not entry.name.isdigit() or int(entry.name) == guest_process.pid:
                    continue
                try:
                    fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
                    if int(fields[2]) == guest_process.pid:
                        os.kill(int(entry.name), 9)
                        killed += 1
                except (OSError, IndexError, ValueError):
                    pass
            out, err = guest_process.communicate('go\n', timeout=60)
            values = parse(''.join(lines) + out)
            ok = killed > 0 and values.get('before') == 0 and all(neg(values.get(k)) for k in
                                                                   ('after', 'after-stat', 'after-child'))
            print('PASS:' if ok else 'FAIL:', f'H {loader.name}: broker killed ({killed} processes)', values)
            ok or failures.append(f'H kill {loader.name}: killed={killed} {values} {err[-300:]}')
            # I: forged requests on a channel of our own.
            checks = {'channel': zero,  # the forged requests below reach the broker 'f-open-outside': neg, 'f-open-dotdot': neg, 'f-magic-nofd': neg,
                      'f-bad-length': neg, 'f-unterminated': neg, 'f-unknown-nr': neg,
                      'f-truncated': neg, 'f-fd-count': neg, 'f-connect-outside': neg,
                      'f-connect-raw-path': neg, 'f-valid-after': lambda x: x == 1,
                      'f-hooked-after': zero}
            if guarded:
                checks.update({'f-open-ro-rw': neg, 'f-link-ro-to-rw': neg})
            expect('I', ('h', 'forge', f'{o}/secret', f'{H["ro"]}/file', f'{H["rw"]}/file',
                         f'{o}/sock'), checks)
            # A host path through a directory link that leaves the trees.
            expect('I', ('h', 'forge', f'{H["rw"]}/out-dir/secret', f'{H["ro"]}/file', f'{H["rw"]}/file',
                         f'{o}/sock'), {'f-open-outside': neg})
            # J: exec.
            p, v = run('h', 'exec', '/ro/prog')
            ok = p.returncode == 2 and 'exec' not in v  # the program ran (no args: exit 2)
            print('PASS:' if ok else 'FAIL:', 'J exec of a readable program', loader.name)
            ok or failures.append(f'J {loader.name}: exec /ro/prog {p.returncode} {v} {p.stderr[-200:]}')
            p, v = run('h', 'execfd', '/ro/prog')
            ok = p.returncode == 2 and 'execfd' not in v
            print('PASS:' if ok else 'FAIL:', 'J fexecve of a readable program', loader.name)
            ok or failures.append(f'J {loader.name}: execfd /ro/prog {p.returncode} {v} {p.stderr[-200:]}')
            if guarded:
                expect('J', ('h', 'exec', '/hidden/prog'), {'exec': neg})
            expect('J', ('d', 'exec', f'{H["ro"]}/prog'), {'exec': eperm})
            # K: FDs of the read-only tree.
            if guarded:
                expect('K', ('h', 'fdops', '/ro/file'),
                       {'open': lambda x: x is not None and x >= 0, 'reopen-rw': neg, 'reopen-ro': zero,
                        'fchmod': neg, 'fchown': neg, 'futimens': neg, 'fsetxattr': neg,
                        'ftruncate': neg, 'write': neg, 'fstat': zero, 'statx-fd': zero,
                        'd-fchmod': eperm, 'd-futimens': eperm, 'd-fsetxattr': eperm})
            # K: closing every FD (closefrom) keeps the broker reachable.
            expect('K', ('h', 'closerange', '/rw/file'),
                     {'close_range': zero, 'closed': lambda x: x == 1, 'after-open': zero})
            # L: UNIX sockets.
            expect('L', ('h', 'bind', '/rw/sock'), {'bind': zero})
            expect('L', ('d', 'connect', f'{o}/sock'), {'connect': eperm})
            expect('L', ('d', 'bind', f'{H["rw"]}/sock2'), {'bind': eperm})
            for leftover in ('sock', 'sock2', 'made-link', 'moved', 'hard', 'hard2', 'stolen'):
                path = base / 'rw' / leftover
                if path.is_symlink() or path.exists():
                    path.unlink()
            (base / 'rw/file').write_text('rw-data\n')
            (base / 'rw/scratch').write_text('scratch\n')
    finally:
        (alpine / 'iso-probe').unlink(missing_ok=True)
        listener.close()

    after = snapshot(base / 'outside', base / 'ro', base / 'hidden')
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    if changed:
        failures.append(f'sentinels changed: {changed}')
    print('FAIL:' if changed else 'PASS:', 'outside/, ro/ and hidden/ unchanged', changed or '')

print(f'{len(failures)} failure(s)')
for f in failures:
    print(' -', f)
raise SystemExit(1 if failures else 0)
