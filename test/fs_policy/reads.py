#!/usr/bin/env python3
"""Default-deny reads, ancestor traversal, filtered listings and stream input."""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']


def tree(root):
    """Host layout. Root and /deny are denied; /home/u/work is rw with a denied
    private child that re-exposes pub read-only; /opt/ro is read-only."""
    for name in ('etc', 'home/u/work', 'home/other', 'opt/ro', 'deny', 'host-work/private',
                 'host-ro', 'host-private/pub', 'host-pub', 'host-deny'):
        (root / name).mkdir(parents=True, exist_ok=True)
    for name, data in (('root-secret', b'SECRET-ROOT'), ('etc/passwd', b'SECRET-ETC'),
                       ('home/u/sibling-secret', b'SECRET-SIB'), ('host-work/file', b'work'),
                       ('host-ro/file', b'ro'), ('host-private/x', b'SECRET-PRIV'),
                       ('host-pub/file', b'pub'), ('host-deny/file', b'SECRET-DENY')):
        (root / name).write_bytes(data)
    (root / 'link-visible').symlink_to('/home/u/work/file')
    (root / 'host-work/to-secret').symlink_to('/root-secret')
    return ['-v', f'{root}/host-work:/home/u/work', '-v', f'{root}/host-ro:/opt/ro',
            '-v', f'{root}/host-private:/home/u/work/private',
            '-v', f'{root}/host-pub:/home/u/work/private/pub',
            '-v', f'{root}/host-deny:/deny']


def launch(root, binds, options, mode):
    secret = os.open(root / 'root-secret', os.O_RDONLY)
    hidden = os.open(root / 'etc', os.O_RDONLY | os.O_DIRECTORY)
    reader, writer = os.pipe()
    os.write(writer, b'PIPE')
    os.close(writer)
    try:
        for source, target in ((secret, 10), (hidden, 11), (reader, 12)):
            os.dup2(source, target)
        return subprocess.run([str(loader), '--mode', 'container', '--root', str(root), *binds,
                               *options, '--', './probe', mode],
                              cwd=root, input=b'IN\n', capture_output=True,
                              pass_fds=(10, 11, 12), timeout=30)
    finally:
        for fd in (secret, hidden, reader, 10, 11, 12):
            os.close(fd)


with tempfile.TemporaryDirectory(prefix='read-guard-', dir=build) as tmp:
    root = Path(tmp)
    binds = tree(root)
    subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', str(repo / 'test/fs_policy/reads.c'),
                    '-o', str(root / 'probe')], check=True)
    (root / 'host-work/probe').write_bytes((root / 'probe').read_bytes())
    (root / 'host-work/probe').chmod(0o755)
    policy = ['--guard-file-access', 'dwrdrd', '--allow-pipe-output', '--allow-stdio-output']
    for mode, extra in (('main', []), ('stream', ['--allow-stream-input'])):
        p = launch(root, binds, [*policy, *extra], mode)
        assert p.returncode == 0, (mode, p.returncode, p.stdout, p.stderr)
        assert b'SECRET' not in p.stdout, p.stdout
        print('PASS: default-deny reads, traversal, listings and inherited FDs:', mode)
    assert (root / 'host-work/file').read_bytes() == b'work'

    # The mutation-only mode keeps its earlier read behavior.
    p = launch(root, binds, ['--guard-file-mutations', 'dwrdrd'], 'main')
    assert p.returncode != 0, (p.stdout, p.stderr)
    print('PASS: file mutation mode does not imply read denial')

    probe = root / 'probe'
    for options, marker in (
            (['--allow-stream-input', '--', str(probe)], 'stream input requires file access guard'),
            (['--guard-file-mutations', 'd', '--allow-stream-input', '--', str(probe)],
             'stream input requires file access guard'),
            (['--guard-file-access', 'd', '--allow-stream-input', '--allow-stream-input',
              '--', str(probe)], 'duplicate stream input option'),
            (['--guard-file-access', 'd', '--guard-file-mutations', 'd', '--', str(probe)],
             'duplicate mount access observation'),
            (['--guard-file-access', 'dw', '--', str(probe)],
             'mount access observation requires root plus every bind')):
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root), *options],
                           capture_output=True, text=True, timeout=20)
        assert p.returncode != 0 and marker in p.stdout + p.stderr, (options, p.stdout, p.stderr)
    print('PASS: invalid file access option combinations rejected')

# Protected rootfs shells: system tree read-only, everything else denied.
for directory, shell, prefix, cat, ls in (
        ('alpine-test-root', './bin/busybox', ['sh'], '/bin/busybox cat', '/bin/busybox ls'),
        ('ubuntu-root', './usr/bin/dash', [], '/usr/bin/cat', '/usr/bin/ls')):
    root = build / directory
    if not (root / shell).exists():
        print('SKIP: protected read rootfs unavailable:', directory)
        continue
    with tempfile.TemporaryDirectory(prefix='read-work-', dir=build) as tmp:
        work = Path(tmp)
        (work / 'note').write_bytes(b'visible-note\n')
        command = (f'{cat} /work/note; printf piped | {cat}; echo; '
                   f'{cat} /etc/passwd 2>/dev/null || echo hidden-etc; '
                   f'{ls} /; v=$({cat} /work/note); echo "sub=$v"; '
                   f'printf out > /work/new; {cat} < /work/new; echo')
        binds = []
        for name in ('bin', 'lib', 'usr', 'sbin'):
            if (root / name).is_dir() and not (root / name).is_symlink():
                binds += ['-v', f'{root}/{name}:/{name}']
        vector = 'd' + 'r' * (len(binds) // 2) + 'w' + 'w'
        p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root), *binds,
                            '-v', f'{work}:/work', '-v', '/dev/null:/dev/null',
                            '--guard-file-access', vector, '--allow-stdio-output',
                            '--allow-pipe-output', '--allow-stream-input',
                            '--revalidate-file-fds', '--', shell, *prefix, '-c', command],
                           cwd=root, capture_output=True, text=True, timeout=30)
        listing = set(p.stdout.split())
        assert p.returncode == 0, (directory, p.returncode, p.stdout, p.stderr)
        assert 'visible-note' in p.stdout and 'piped' in p.stdout, p.stdout
        assert 'hidden-etc' in p.stdout and 'sub=visible-note' in p.stdout, p.stdout
        assert 'out' in p.stdout.splitlines(), p.stdout
        # Bind targets absent from the host root have no glue entry yet.
        assert 'etc' not in listing and 'root' not in listing and 'usr' in listing, p.stdout
        assert 'root:' not in p.stdout, p.stdout
        print('PASS: protected rootfs reads, pipes, listing and redirection:', directory)
