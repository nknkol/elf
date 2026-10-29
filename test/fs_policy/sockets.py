#!/usr/bin/env python3
"""UNIX socket pathnames: guest translation, long host paths and policy."""
import hashlib
import json
import socket
import stat
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'


def loader(suffix):
    path = build / f'elfloader-proot{suffix}'
    manifest = build / f'elf-build{suffix}.json'
    if not path.exists() or not manifest.exists():
        return None
    if hashlib.sha256(path.read_bytes()).hexdigest() != json.loads(manifest.read_text())['sha256']:
        return None
    return path


def socket_capable():
    """Some backings refuse socket inodes (HarmonyOS /storage/Users, /tmp)."""
    for base in (build, Path(tempfile.gettempdir()), Path('/data/storage/el2/base/cache')):
        try:
            with tempfile.TemporaryDirectory(prefix='sock-probe-', dir=base) as tmp:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.bind(str(Path(tmp) / 's'))
            return base
        except OSError:
            continue
    return None


experiment = loader('-fd-experiment')
assert experiment, 'build the FD experiment first'
base = socket_capable()
if base is None:
    print('SKIP: no backing directory accepts UNIX socket files')
    raise SystemExit(0)
with tempfile.TemporaryDirectory(prefix='sock-', dir=base) as tmp:
    root = Path(tmp)
    for name in ('w', 'r', 'host-w', 'host-r'):
        (root / name).mkdir()
    # Guest path stays short; its host spelling exceeds sun_path (108 bytes).
    deep = 'a' * max(8, 112 - len(str(root / 'host-w')))
    assert len(f'/w/{deep}/s') < 108, 'guest path must fit sun_path'
    (root / 'host-w' / deep).mkdir()
    longpath = f'/w/{deep}/s'
    assert len(str(root / 'host-w' / deep / 's')) >= 108, 'fixture must exceed sun_path'
    (root / 'host-w/link').symlink_to('/w/t')
    services = []
    for name, kind in (('hostsvc.sock', socket.SOCK_STREAM), ('hostdgram.sock', socket.SOCK_DGRAM)):
        service = socket.socket(socket.AF_UNIX, kind)
        service.bind(str(root / name))
        if kind == socket.SOCK_STREAM:
            service.listen(4)
        services.append(service)
    hostpath = str(root / 'hostsvc.sock')
    subprocess.run(['clang', '-D_GNU_SOURCE', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector', str(repo / 'test/fs_policy/sockets.c'),
                    '-o', str(root / 'probe')], check=True)
    binds = ['-v', f'{root}/host-w:/w', '-v', f'{root}/host-r:/r']

    def run(path, mode, options):
        return subprocess.run([str(path), '--mode', 'container', '--root', str(root), *binds,
                               *options, '--', './probe', mode, longpath, hostpath],
                              cwd=root, capture_output=True, timeout=30)

    def clean():
        for name in ('s1', 's2', 't', 'd', f'{deep}/s'):
            (root / 'host-w' / name).unlink(missing_ok=True)

    cases = [(experiment, 'guard', ['--guard-file-access', 'dwr']),
             (experiment, 'plain', [])]
    default = loader('')
    if default:
        cases.append((default, 'plain', []))
    for path, mode, options in cases:
        clean()
        p = run(path, mode, options)
        assert p.returncode == 0, (path.name, mode, p.returncode, p.stdout, p.stderr)
        for name in ('s1', 's2', 't', 'd', f'{deep}/s'):
            assert stat.S_ISSOCK((root / 'host-w' / name).lstat().st_mode), name
        # Nothing was created at the raw guest spellings on the host side.
        assert not (root / 'w' / 's1').exists() and not list((root / 'host-r').iterdir())
        assert not (root / 'denied.sock').exists()
        print('PASS: UNIX socket paths translated with policy:', path.name, mode)
    if not default:
        print('SKIP: default build not available for plain translation')
    for service in services:
        service.close()
