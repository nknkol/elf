#!/usr/bin/env python3
"""Acceptance of the docker command (docs/OCI.md, R1 and R2 checks).

Expected outcomes:
- unpack: whiteouts, opaque directories, file/directory swaps, hard links
  as copies, skipped device nodes, modes and symlink chains give exactly the
  expected tree;
- unpack safety: absolute names, "..", writes through symlinks (same layer
  and earlier layer), hard links out of the tree and oversized images are
  refused and leave nothing outside the rootfs;
- verification: a tampered blob or a wrong diff_id fails pull and load;
  pull works through bearer-token auth and resumes a partial blob;
- config mapping: Entrypoint/Cmd/--entrypoint, Env/-e/--env-file,
  WorkingDir/-w, User/-u (names and numbers), volumes, hostname; refused
  options exit 125; plain and --isolate;
- lifecycle: run -d, logs, exec, stop (signal, then timeout), restart
  policy, wait, cp, named volumes, --read-only, --in-place, rm, prune.
Needs a case-sensitive directory: ELF_OCI_TEST_HOME, default
/data/storage/el2/base/files/elf-oci-test (else a temporary directory)."""
import gzip
import hashlib
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

DOCKER = lib.REPO / 'tools/oci/docker'
DEFAULT_HOME = Path('/data/storage/el2/base/files/elf-oci-test')
failures = []


def check(cond, what, detail=''):
    if cond:
        print('PASS:', what)
    else:
        print('FAIL:', what, detail)
        failures.append(what)


# ------------------------------------------------------------ fixtures
def member(name, kind='file', data=b'', mode=None, link='', uid=0, gid=0, mtime=1700000000):
    info = tarfile.TarInfo(name)
    info.mtime, info.uid, info.gid = mtime, uid, gid
    if kind == 'file':
        info.size, info.mode = len(data), 0o644 if mode is None else mode
        return info, data
    info.type = {'dir': tarfile.DIRTYPE, 'sym': tarfile.SYMTYPE, 'hard': tarfile.LNKTYPE,
                 'chr': tarfile.CHRTYPE, 'fifo': tarfile.FIFOTYPE}[kind]
    info.mode = (0o755 if kind == 'dir' else 0o644) if mode is None else mode
    info.linkname = link
    return info, None


def layer_bytes(members, compress=True):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    plain = raw.getvalue()
    blob = gzip.compress(plain, mtime=0) if compress else plain
    return blob, 'sha256:' + hashlib.sha256(plain).hexdigest()


def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def oci_layout(path, layers, config=None, name='test/img:1', tamper_diff=False):
    """An OCI layout directory with the given (blob, diff_id) layers."""
    blobs = path / 'blobs' / 'sha256'
    blobs.mkdir(parents=True)
    diff_ids = [d for _, d in layers]
    if tamper_diff:
        diff_ids[-1] = 'sha256:' + '0' * 64
    cfg = {'architecture': 'arm64', 'os': 'linux', 'created': '2026-01-01T00:00:00Z',
           'config': config or {'Cmd': ['/bin/sh']},
           'rootfs': {'type': 'layers', 'diff_ids': diff_ids},
           'history': [{'created': '2026-01-01T00:00:00Z', 'created_by': 'test'}]}
    cfg_bytes = json.dumps(cfg).encode()
    (blobs / sha(cfg_bytes)[7:]).write_bytes(cfg_bytes)
    descs = []
    for blob, _ in layers:
        (blobs / sha(blob)[7:]).write_bytes(blob)
        descs.append({'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip',
                      'digest': sha(blob), 'size': len(blob)})
    manifest = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                'config': {'mediaType': 'application/vnd.oci.image.config.v1+json',
                           'digest': sha(cfg_bytes), 'size': len(cfg_bytes)}, 'layers': descs}
    m_bytes = json.dumps(manifest).encode()
    (blobs / sha(m_bytes)[7:]).write_bytes(m_bytes)
    (path / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}')
    (path / 'index.json').write_text(json.dumps({'schemaVersion': 2, 'manifests': [
        {'mediaType': manifest['mediaType'], 'digest': sha(m_bytes), 'size': len(m_bytes),
         'annotations': {'io.containerd.image.name': 'docker.io/' + name}}]}))
    return cfg_bytes, m_bytes


def docker(home, *args, input=None, timeout=300, env=None):
    return subprocess.run([sys.executable, '-B', str(DOCKER), *args], capture_output=True, text=True,
                          input=input, timeout=timeout,
                          env=dict(os.environ, ELF_OCI_HOME=str(home), **(env or {})))


def tree(root):
    out = {}
    for top, dirs, files in os.walk(root):
        for name in dirs + files:
            p = Path(top, name)
            rel = '/' + str(p.relative_to(root))
            if rel == '/.elf-exec':
                continue
            if p.is_symlink():
                out[rel] = ('sym', os.readlink(p))
            elif p.is_dir():
                out[rel] = ('dir',)
            else:
                out[rel] = ('file', p.read_bytes())
    return out


def image_root(home, name):
    p = docker(home, 'inspect', '-f', '{{.GraphDriver.Data.Rootfs}}', name)
    return Path(p.stdout.strip())


# ------------------------------------------------------------ unpack
def unpack_tests(home, work):
    l1, d1 = layer_bytes([
        member('etc', 'dir'), member('etc/keep', data=b'keep'), member('etc/gone', data=b'gone'),
        member('opq', 'dir'), member('opq/old', data=b'old'), member('opq/sub', 'dir'),
        member('opq/sub/deep', data=b'deep'),
        member('swap1', data=b'was file'), member('swap2', 'dir'), member('swap2/x', data=b'x'),
        member('bin', 'dir'), member('bin/tool', data=b'#!tool', mode=0o4755),
        member('bin/hard', 'hard', link='bin/tool'), member('bin/data', data=b'data'),
        member('bin/data2', 'hard', link='bin/data'),
        member('dev', 'dir'), member('dev/null', 'chr'), member('dev/fifo', 'fifo'),
        member('chain1', 'sym', link='chain2'), member('chain2', 'sym', link='/etc/keep'),
        member('owned', data=b'o', uid=1000, gid=1000),
        member('ro_dir', 'dir', mode=0o555), member('ro_dir/f', data=b'f', mode=0o444)])
    l2, d2 = layer_bytes([
        member('etc/.wh.gone'), member('opq', 'dir'), member('opq/.wh..wh..opq'),
        member('opq/new', data=b'new'),
        member('swap1', 'dir'), member('swap1/in', data=b'now dir'), member('swap2', data=b'now file'),
        member('etc/keep', data=b'kept v2')])
    layout = work / 'good'
    oci_layout(layout, [(l1, d1), (l2, d2)], name='test/unpack:1')
    p = docker(home, 'load', '-i', str(layout))
    check(p.returncode == 0 and 'Loaded image: test/unpack:1' in p.stdout, 'load of an OCI layout',
          p.stdout + p.stderr)
    root = image_root(home, 'test/unpack:1')
    got = tree(root)
    expected = {
        '/etc': ('dir',), '/etc/keep': ('file', b'kept v2'),
        '/opq': ('dir',), '/opq/new': ('file', b'new'),
        '/swap1': ('dir',), '/swap1/in': ('file', b'now dir'), '/swap2': ('file', b'now file'),
        '/bin': ('dir',), '/bin/tool': ('file', b'#!tool'), '/bin/hard': ('sym', '/bin/tool'),
        '/bin/data': ('file', b'data'), '/bin/data2': ('file', b'data'),
        '/dev': ('dir',), '/chain1': ('sym', 'chain2'), '/chain2': ('sym', '/etc/keep'),
        '/owned': ('file', b'o'), '/ro_dir': ('dir',), '/ro_dir/f': ('file', b'f')}
    check(got == expected, 'unpack: whiteout, opaque, swaps, hard links (symlink to executables, else copy), '
          'devices skipped, links',
          f'{set(got) ^ set(expected)} {[(k, got.get(k), v) for k, v in expected.items() if got.get(k) != v]}')
    meta = json.loads((root.parent / 'meta.json').read_text())
    check(meta['hardlinks'] == {'/bin/hard': '/bin/tool', '/bin/data2': '/bin/data'} and meta['owners'] == {'/owned': [1000, 1000]}
          and set(meta['skipped']) == {'/dev/null', '/dev/fifo'} and meta['modes'].get('/ro_dir') == 0o555,
          'unpack metadata: hard links, owners, skipped entries, guest modes', meta)
    check(os.stat(root / 'ro_dir').st_mode & 0o700 == 0o700, 'unpacked directories stay writable by the owner')

    sentinel = work / 'sentinel'
    sentinel.mkdir()
    (sentinel / 'canary').write_text('c')
    before = tree(sentinel)
    escape = os.path.relpath(sentinel, '/')
    bad_layers = {
        'absolute name': [member('/' + escape + '/abs', data=b'x')],
        'dot-dot name': [member('../../../../../../../../' + escape + '/dd', data=b'x')],
        'write through a symlink in the same layer': [member('link', 'sym', link=str(sentinel)),
                                                      member('link/through', data=b'x')],
        'hard link out of the tree': [member('h', 'hard', link='../../../../../../../../' + escape + '/canary')],
    }
    for what, members in bad_layers.items():
        blob, diff = layer_bytes(members)
        d = work / ('bad-' + what.replace(' ', '-'))
        oci_layout(d, [(blob, diff)], name='test/bad:1')
        p = docker(home, 'load', '-i', str(d))
        # A symlink-replacing write is not an error: the link is replaced.
        landed = tree(sentinel) != before
        if what.startswith('write through'):
            check(not landed, f'unpack safety: {what} stays inside', p.stderr)
        else:
            check(p.returncode != 0 and not landed, f'unpack safety: {what} refused', p.stderr[-300:])
    # Earlier layer's symlink, later layer writes beneath it.
    la, da = layer_bytes([member('esc', 'sym', link=str(sentinel))])
    lb, db = layer_bytes([member('esc/x', data=b'x')])
    d = work / 'bad-cross'
    oci_layout(d, [(la, da), (lb, db)], name='test/cross:1')
    p = docker(home, 'load', '-i', str(d))
    check(tree(sentinel) == before, 'unpack safety: write beneath an earlier layer\'s symlink stays inside',
          p.stderr)
    big, dbig = layer_bytes([member('big', data=b'x' * 4096)])
    d = work / 'bad-big'
    oci_layout(d, [(big, dbig)], name='test/big:1')
    p = docker(home, 'load', '-i', str(d), env={'ELF_OCI_MAX_BYTES': '1000'})
    check(p.returncode != 0 and 'exceeds' in p.stderr, 'unpack safety: size limit', p.stderr[-200:])
    d = work / 'bad-diff'
    oci_layout(d, [(l1, d1)], name='test/diff:1', tamper_diff=True)
    p = docker(home, 'load', '-i', str(d))
    check(p.returncode != 0 and 'diff_id' in p.stderr, 'load: diff_id mismatch refused', p.stderr[-200:])
    leftovers = [x for x in (home / 'tmp').iterdir()]
    check(not leftovers, 'failed loads leave no temporary trees', leftovers)
    return l1, d1


# ------------------------------------------------------------ registry
class Registry(http.server.BaseHTTPRequestHandler):
    blobs, manifests, tamper = {}, {}, set()
    token = 'secret-token'

    def log_message(self, *args):
        pass

    users = {}   # Basic credentials the token endpoint accepts (empty: anyone).

    def authorized(self):
        if self.headers.get('Authorization') == f'Bearer {self.token}':
            return True
        self.send_response(401)
        port = self.server.server_address[1]
        self.send_header('WWW-Authenticate', f'Bearer realm="http://127.0.0.1:{port}/token",service="test"')
        self.send_header('Content-Length', '0')
        self.end_headers()
        return False

    def do_HEAD(self):
        if not self.authorized():
            return
        digest = self.path.split('/')[-1]
        self.send_response(200 if digest in self.blobs else 404)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        if not self.authorized():
            return
        self.send_response(202)
        self.send_header('Location', '/v2/upload/session-1')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_PUT(self):
        if not self.authorized():
            return
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if '/manifests/' in self.path:
            self.manifests[self.path.split('/')[-1]] = (body, self.headers['Content-Type'])
            self.manifests[sha(body)] = (body, self.headers['Content-Type'])
        else:
            digest = self.path.split('digest=')[1].replace('%3A', ':')
            if sha(body) != digest:
                return self.reply(400, b'{"errors":[{"code":"DIGEST_INVALID"}]}')
            self.blobs[digest] = body
        self.reply(201, b'')

    def do_GET(self):
        if self.path.startswith('/token'):
            import base64
            given = self.headers.get('Authorization', '')
            if self.users and given not in ['Basic ' + base64.b64encode(f'{u}:{pw}'.encode()).decode()
                                            for u, pw in self.users.items()]:
                return self.reply(401, b'{}')
            body = json.dumps({'token': self.token}).encode()
            return self.reply(200, body, 'application/json')
        if self.path == '/v2/':
            return self.reply(200, b'{}') if self.authorized() else None
        if self.headers.get('Authorization') != f'Bearer {self.token}':
            self.send_response(401)
            port = self.server.server_address[1]
            self.send_header('WWW-Authenticate', f'Bearer realm="http://127.0.0.1:{port}/token",'
                             'service="test"')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        parts = self.path.split('/')
        if '/manifests/' in self.path:
            body, media = self.manifests.get(parts[-1], (None, None))
            return self.reply(200, body, media) if body else self.reply(404, b'{}')
        if '/blobs/' in self.path:
            digest = parts[-1]
            body = self.blobs.get(digest)
            if body is None:
                return self.reply(404, b'{}')
            if digest in self.tamper:
                body = body[:-1] + bytes([body[-1] ^ 1])
            start = 0
            if self.headers.get('Range'):
                start = int(self.headers['Range'].split('=')[1].split('-')[0])
                self.send_response(206)
            else:
                self.send_response(200)
            self.send_header('Content-Length', str(len(body) - start))
            self.end_headers()
            self.wfile.write(body[start:])
            return
        self.reply(404, b'{}')

    def reply(self, code, body, media='application/json'):
        self.send_response(code)
        self.send_header('Content-Type', media)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def registry_tests(home, work):
    blob, diff = layer_bytes([member('pulled', data=os.urandom(4096))])
    layout = work / 'reg'
    cfg, manifest = oci_layout(layout, [(blob, diff)], name='x')
    Registry.blobs = {sha(cfg): cfg, sha(blob): blob}
    index = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
                        'manifests': [
                            {'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': sha(b'{}'),
                             'size': 2, 'platform': {'os': 'linux', 'architecture': 'amd64'}},
                            {'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                             'digest': sha(manifest), 'size': len(manifest),
                             'platform': {'os': 'linux', 'architecture': 'arm64'}}]}).encode()
    Registry.manifests = {'1': (index, 'application/vnd.oci.image.index.v1+json'),
                          sha(manifest): (manifest, 'application/vnd.oci.image.manifest.v1+json')}
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Registry)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        Registry.tamper = {sha(blob)}
        p = docker(home, 'pull', f'localhost:{port}/test/reg:1')
        check(p.returncode != 0 and 'does not match' in p.stderr, 'pull: tampered blob refused', p.stderr[-300:])
        Registry.tamper = set()
        # A partial download resumes with Range.
        part = home / 'blobs' / 'sha256' / (sha(blob)[7:] + '.part')
        part.write_bytes(blob[:len(blob) // 2])
        p = docker(home, 'pull', f'localhost:{port}/test/reg:1')
        check(p.returncode == 0, 'pull: bearer token, platform index, resumed blob', p.stderr[-300:])
        p = docker(home, 'images', '--format', '{{.Repository}}:{{.Tag}}')
        check(f'localhost:{port}/test/reg:1' in p.stdout.split(), 'pulled image is listed', p.stdout)
        # login, then push under a new name and pull it back.
        Registry.users = {'alice': 'pw'}
        config_dir = work / 'docker-config'
        env = {'DOCKER_CONFIG': str(config_dir)}
        p = docker(home, 'login', '-u', 'alice', '--password-stdin', f'localhost:{port}', input='wrong\n', env=env)
        check(p.returncode != 0, 'login: wrong password refused', p.stdout + p.stderr)
        p = docker(home, 'login', '-u', 'alice', '--password-stdin', f'localhost:{port}', input='pw\n', env=env)
        check(p.returncode == 0 and 'Login Succeeded' in p.stdout and
              (config_dir / 'config.json').stat().st_mode & 0o077 == 0, 'login: stored (mode 0600)', p.stderr)
        docker(home, 'tag', f'localhost:{port}/test/reg:1', f'localhost:{port}/test/pushed:2')
        p = docker(home, 'push', f'localhost:{port}/test/pushed:2', env=env)
        check(p.returncode == 0 and '2' in Registry.manifests, 'push: blobs and manifest uploaded', p.stderr[-300:])
        docker(home, 'rmi', f'localhost:{port}/test/pushed:2', f'localhost:{port}/test/reg:1')
        docker(home, 'image', 'prune', '-af')
        p = docker(home, 'pull', f'localhost:{port}/test/pushed:2', env=env)
        check(p.returncode == 0, 'push: the pushed image pulls back', p.stderr[-300:])
        Registry.users = {}
    finally:
        server.shutdown()


# ------------------------------------------------------------ running
def root_owned(info):
    """Image files belong to root, as in real images (not the app uid)."""
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    return info


def layer_owners(home, image, work):
    """{path: (uid, gid, mode)} of the last layer of a saved image."""
    archive = work / 'owners-save.tar'
    p = docker(home, 'save', '-o', str(archive), image)
    assert p.returncode == 0, p.stderr
    with tarfile.open(archive) as outer:
        manifest = json.load(outer.extractfile('manifest.json'))
        blob = outer.extractfile(manifest[0]['Layers'][-1]).read()
    if blob[:2] == b'\x1f\x8b':
        blob = gzip.decompress(blob)
    with tarfile.open(fileobj=io.BytesIO(blob)) as layer:
        return {m.name.rstrip('/'): (m.uid, m.gid, m.mode) for m in layer}


def mount_owner_tests(home, work):
    """R4 mounts inside containers, R5 owners (docs/OCI.md)."""
    img = 'test/alpine:1'
    for mode in ([], ['--isolate']):
        tag = ' (--isolate)' if mode else ''
        p = docker(home, 'run', '--rm', *mode, '-u', 'root', img,
                   'mkdir -p /mnt/t /mnt/b && mount -t tmpfs -o mode=0700 none /mnt/t && echo x > /mnt/t/f && '
                   'mount --bind /etc /mnt/b && grep -c " /mnt/" /proc/mounts && stat -c %a /mnt/t && '
                   'ls /mnt/b/alpine-release && umount /mnt/t && umount /mnt/b && ls /mnt/t | wc -l && '
                   'grep -c " /mnt/" /proc/mounts; mount -t ext4 /dev/sda /mnt/t 2>/dev/null || echo refused')
        check(p.returncode == 0 and p.stdout == '2\n700\n/mnt/b/alpine-release\n0\n0\nrefused\n',
              'mount: tmpfs, --bind, /proc/mounts, umount, unsupported type' + tag, p.stdout + p.stderr)
    # docker exec joins the container's mounts.
    name = 'mounter'
    docker(home, 'run', '-d', '--name', name, '-u', 'root', img,
           'mkdir -p /mnt/x; mount -t tmpfs none /mnt/x; echo shared > /mnt/x/f; sleep 30')
    time.sleep(1.5)
    p = docker(home, 'exec', name, 'cat', '/mnt/x/f')
    cdir = home / 'containers' / docker(home, 'inspect', '-f', '{{.Id}}', name).stdout.strip()
    check(p.stdout == 'shared\n' and not (cdir / 'rootfs/mnt/x/f').exists(),
          'mount: docker exec sees the container\'s mounts; the rootfs does not', p.stdout + p.stderr)
    docker(home, 'stop', '-t', '1', name)
    docker(home, 'rm', '-f', name)
    # R5: an image with owners and modes the host cannot hold.
    docker(home, 'save', '-o', str(work / 'alpine-base.tar'), img)
    with tarfile.open(work / 'alpine-base.tar') as outer:
        manifest = json.load(outer.extractfile('manifest.json'))
        base_blob = outer.extractfile(manifest[0]['Layers'][0]).read()
    plain_base = gzip.decompress(base_blob) if base_blob[:2] == b'\x1f\x8b' else base_blob
    extra, extra_id = layer_bytes([member('srv/', 'dir'), member('srv/owned', data=b'o', mode=0o640,
                                                                 uid=1000, gid=1001),
                                   member('srv/suid', data=b's', mode=0o4755),
                                   member('srv/locked', 'dir', mode=0o500, uid=70, gid=70)])
    oci_layout(work / 'owned', [(base_blob, sha(plain_base)), (extra, extra_id)],
               {'Entrypoint': ['/bin/sh', '-c'], 'Env': ['PATH=/usr/sbin:/usr/bin:/sbin:/bin']},
               name='test/owned:1')
    p = docker(home, 'load', '-i', str(work / 'owned'))
    check(p.returncode == 0, 'owners: image with recorded owners loads', p.stderr)
    probe = 'stat -c "%n %u %g %a" /srv/owned /srv/suid /srv/locked; stat -c "%n %u %g" /etc/passwd'
    for mode in ([], ['--isolate']):
        tag = ' (--isolate)' if mode else ''
        p = docker(home, 'run', '--rm', '--owners', *mode, 'test/owned:1', probe)
        check(p.stdout == '/srv/owned 1000 1001 640\n/srv/suid 0 0 4755\n/srv/locked 70 70 500\n'
              '/etc/passwd 0 0\n', '--owners: stat reports the image\'s owners and modes' + tag,
              p.stdout + p.stderr)
        p = docker(home, 'run', '--rm', '--owners', *mode, '-u', 'root', 'test/owned:1',
                   'adduser -D -u 1234 pg && mkdir /data && chown pg:pg /data && chmod 700 /data && '
                   'su pg -s /bin/sh -c "touch /data/x; stat -c \'%U %a\' /data /data/x; '
                   'chown root /data/x 2>/dev/null || echo eperm"')
        check(p.stdout == 'pg 700\npg 644\neperm\n',
              '--owners: chown, chmod, a user\'s new files, EPERM to give away' + tag, p.stdout + p.stderr)
    p = docker(home, 'run', '--rm', 'test/owned:1', 'stat -c "%u %g" /srv/owned')
    check(p.stdout == '0 0\n', 'without --owners every file reads as root\'s (fake_id0)', p.stdout + p.stderr)
    # commit writes the recorded owners into the layer.
    docker(home, 'run', '--owners', '--name', 'chowner', '-u', 'root', 'test/owned:1',
           'echo c > /srv/new && chown 4321:4322 /srv/new && chmod 4711 /srv/new && chown 99 /srv/owned')
    p = docker(home, 'diff', 'chowner')
    check({'A /srv/new', 'C /srv/owned'} <= set(p.stdout.splitlines()),
          'diff: an owner change alone is a change', p.stdout + p.stderr)
    p = docker(home, 'commit', 'chowner', 'test/chowned:1')
    heads = layer_owners(home, 'test/chowned:1', work) if p.returncode == 0 else {}
    check(heads.get('srv/new') == (4321, 4322, 0o4711) and heads.get('srv/owned', (0,))[:2] == (99, 1001),
          'commit: layer tar headers carry the recorded owners and modes', str(heads) + p.stderr)
    p = docker(home, 'run', '--rm', '--owners', 'test/chowned:1', 'stat -c "%u %g %a" /srv/new /srv/locked')
    check(p.stdout == '4321 4322 4711\n70 70 500\n', 'commit: the new image keeps the owners', p.stdout + p.stderr)
    docker(home, 'rm', 'chowner')
    # build: chown in RUN and COPY --chown reach the layers.
    ctx = work / 'owners-ctx'
    ctx.mkdir()
    (ctx / 'file').write_text('f\n')
    (ctx / 'Dockerfile').write_text('FROM test/alpine:1\nUSER root\n'
                                    'RUN adduser -D -u 2345 app && mkdir /app && chown app:app /app && '
                                    'chmod 750 /app\nCOPY --chown=2345:2346 file /app/file\n'
                                    'COPY --chown=app file /app/named\n')
    p = docker(home, 'build', '-q', '-t', 'test/owners-built:1', str(ctx), timeout=600)
    heads = layer_owners(home, 'test/owners-built:1', work) if p.returncode == 0 else {}
    check(heads.get('app/named', (0, 0))[:2] == (2345, 2345), 'build: COPY --chown=name', str(heads) + p.stderr)
    p2 = docker(home, 'run', '--rm', '--owners', 'test/owners-built:1', 'stat -c "%n %u %g %a" /app /app/file')
    check(p2.stdout == '/app 2345 2345 750\n/app/file 2345 2346 644\n',
          'build: chown in RUN and COPY --chown in the image', p2.stdout + p2.stderr + p.stderr)
    for image in ('test/owners-built:1', 'test/chowned:1', 'test/owned:1'):
        docker(home, 'rmi', '-f', image)


def cow_tests(home, work):
    """R6: --cow containers share the image rootfs (docs/OCI.md)."""
    img = 'test/alpine:1'
    root = image_root(home, img)
    for mode in ([], ['--isolate']):
        tag = ' (--isolate)' if mode else ''
        before = tree(root)
        name = 'cow' + ('-isolate' if mode else '')
        p = docker(home, 'run', '--cow', *mode, '--name', name, '-u', 'root', img,
                   'echo changed > /etc/motd && rm /etc/issue && mkdir -p /srv/app/new && echo y > /srv/app/new/f '
                   '&& cat /etc/motd && ls /etc | grep -c "^issue$"; true')
        cid = docker(home, 'inspect', '-f', '{{.Id}}', name).stdout.strip()
        cdir = home / 'containers' / cid
        check(p.returncode == 0 and p.stdout == 'changed\n0\n' and not (cdir / 'rootfs').exists() and
              (cdir / 'upper/etc/motd').read_text() == 'changed\n' and (cdir / 'upper/etc/.wh.issue').exists()
              and tree(root) == before,
              '--cow: writes go to the upper layer, nothing copied, the image rootfs unchanged' + tag,
              p.stdout + p.stderr)
        p = docker(home, 'run', '--rm', '--cow', *mode, img, 'cat /etc/issue | wc -l; grep -c changed /etc/motd')
        check(p.stdout.split()[1:] == ['0'] and p.stdout.split()[0] != '0',
              '--cow: another container of the image sees none of it' + tag, p.stdout + p.stderr)
        p = docker(home, 'diff', name)
        check({'C /etc/motd', 'D /etc/issue', 'A /srv/app/new/f'} <= set(p.stdout.splitlines()),
              '--cow: diff' + tag, p.stdout + p.stderr)
        (work / 'cow-in').write_text('in\n')
        p = docker(home, 'cp', str(work / 'cow-in'), f'{name}:/usr/share/')
        p2 = docker(home, 'cp', f'{name}:/etc/motd', str(work / 'cow-out'))
        check(p.returncode == 0 and (cdir / 'upper/usr/share/cow-in').read_text() == 'in\n' and
              p2.returncode == 0 and (work / 'cow-out').read_text() == 'changed\n',
              '--cow: cp in (to the upper) and out (merged view)' + tag, p.stderr + p2.stderr)
        image = f'test/cow{"-isolate" if mode else ""}:1'
        p = docker(home, 'commit', name, image)
        p2 = docker(home, 'run', '--rm', '--cow', *mode, image,
                    'cat /etc/motd /usr/share/cow-in /srv/app/new/f; test -e /etc/issue || echo gone')
        check(p.returncode == 0 and p2.stdout == 'changed\nin\ny\ngone\n',
              '--cow: commit makes an image of the merged view' + tag, p.stdout + p.stderr + p2.stdout + p2.stderr)
        docker(home, 'rm', name)
        docker(home, 'rmi', '-f', image)
    p = docker(home, 'run', '--rm', '--cow', '--owners', '-u', 'root', img,
               'chown 1234:5 /etc/motd && chmod 600 /etc/motd && stat -c "%u %g %a" /etc/motd; stat -c %u /etc/fstab')
    check(p.stdout == '1234 5 600\n0\n' and tree(root) == before,
          '--cow --owners: chown/chmod of a lower file recorded', p.stdout + p.stderr)
    p = docker(home, 'run', '--rm', '--cow', '--read-only', img, 'true')
    check(p.returncode == 125, '--cow with --read-only is refused', p.stderr)


def alpine_image(home, work):
    root = lib.require(lib.ALPINE, 'Alpine test rootfs')
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as tar:
        for top, dirs, files in os.walk(root):
            for name in sorted(dirs + files):
                p = Path(top, name)
                rel = str(p.relative_to(root))
                if rel.startswith('.elf'):
                    continue
                tar.add(str(p), rel, recursive=False, filter=root_owned)
    plain = raw.getvalue()
    blob = gzip.compress(plain, mtime=0, compresslevel=1)
    config = {'Entrypoint': ['/bin/sh', '-c'], 'Cmd': ['echo default-cmd'],
              'Env': ['PATH=/usr/sbin:/usr/bin:/sbin:/bin', 'FROM_IMAGE=yes'],
              'WorkingDir': '/srv/app', 'User': 'nobody', 'StopSignal': 'SIGUSR1'}
    oci_layout(work / 'alpine', [(blob, sha(plain))], config, name='test/alpine:1')
    p = docker(home, 'load', '-i', str(work / 'alpine'))
    assert p.returncode == 0, p.stderr


def run_tests(home, work, isolate):
    mode = ['--isolate'] if isolate else []
    tag = ' (--isolate)' if isolate else ''
    img = 'test/alpine:1'
    p = docker(home, 'run', '--rm', *mode, img)
    check(p.returncode == 0 and p.stdout == 'default-cmd\n', 'Entrypoint + Cmd' + tag, p.stdout + p.stderr)
    p = docker(home, 'run', '--rm', *mode, img, 'echo $FROM_IMAGE $(id -un) $(pwd) $HOME')
    check(p.stdout == 'yes nobody /srv/app /\n', 'arguments replace Cmd; Env, User, WorkingDir' + tag,
          p.stdout + p.stderr)
    envfile = work / 'env'
    envfile.write_text('# comment\n\nA=1\nB="two"\nFROM_HOST\n')
    p = docker(home, 'run', '--rm', *mode, '--entrypoint', '/bin/sh', '-u', '1234:5678', '-w', '/tmp',
               '-e', 'C=3', '--env-file', str(envfile), '-h', 'box', img,
               '-c', 'echo $A $B $C $FROM_HOST; id -u; id -g; pwd; hostname; cat /etc/hostname',
               env={'FROM_HOST': 'host-value'})
    check(p.stdout == '1 "two" 3 host-value\n1234\n5678\n/tmp\nbox\nbox\n',
          '--entrypoint, -u numbers, -w, -e, --env-file, -h' + tag, p.stdout + p.stderr)
    vol = work / 'vol'
    vol.mkdir(exist_ok=True)
    (vol / 'in').write_text('host data')
    p = docker(home, 'run', '--rm', *mode, '-u', 'root', '-v', f'{vol}:/data', '-v', f'{vol}:/ro:ro', img,
               'cat /data/in; echo out > /data/out; echo x > /ro/x 2>/dev/null || echo ro-refused')
    check(p.stdout == 'host dataro-refused\n' and
          (vol / 'out').read_text() == 'out\n' and not (vol / 'x').exists(),
          'volumes rw and :ro' + tag, p.stdout + p.stderr)
    p = docker(home, 'run', '--rm', *mode, '--entrypoint', '', img, 'no-such-command')
    check(p.returncode == 127, 'missing command exits 127' + tag, p.stderr)
    p = docker(home, 'run', '--rm', *mode, img, 'exit 42')
    check(p.returncode == 42, 'container exit status' + tag)
    for flag in (['--privileged'], ['--memory', '1g'], ['-p', '8080:80'], ['--network', 'none']):
        p = docker(home, 'run', '--rm', *mode, *flag, img)
        check(p.returncode == 125 and 'not supported' in p.stderr, f'{flag[0]} refused with 125' + tag,
              p.stderr)
    # Lifecycle.
    name = 'life' + ('-iso' if isolate else '')
    p = docker(home, 'run', '-d', *mode, '--name', name, '-u', 'root', img,
               'trap "echo got-usr1; exit 9" USR1; echo started; while :; do sleep 0.2; done')
    check(p.returncode == 0 and len(p.stdout.strip()) == 64, 'run -d prints the id' + tag, p.stderr)
    time.sleep(1)
    p = docker(home, 'ps', '--format', '{{.Names}} {{.State}}')
    check(f'{name} running' in p.stdout, 'ps shows the running container' + tag, p.stdout)
    p = docker(home, 'exec', name, 'sh', '-c', 'echo $FROM_IMAGE; hostname')
    check(p.returncode == 0 and p.stdout.startswith('yes\n'), 'exec in the container' + tag, p.stderr)
    (work / 'cpfile').write_text('copied')
    p = docker(home, 'cp', str(work / 'cpfile'), f'{name}:/root/')
    p2 = docker(home, 'exec', name, 'cat', '/root/cpfile')
    check(p.returncode == 0 and p2.stdout == 'copied', 'cp into the container' + tag, p.stderr + p2.stderr)
    p = docker(home, 'cp', f'{name}:/etc/alpine-release', str(work / 'release'))
    check(p.returncode == 0 and (work / 'release').read_text().strip()[0].isdigit(), 'cp out of the container' + tag)
    p = docker(home, 'stop', name)          # StopSignal SIGUSR1 from the image.
    p2 = docker(home, 'inspect', '-f', '{{.State.Status}} {{.State.ExitCode}}', name)
    p3 = docker(home, 'logs', name)
    check(p2.stdout.strip() == 'exited 9' and 'started' in p3.stdout and 'got-usr1' in p3.stdout,
          'stop sends the StopSignal; logs kept' + tag, p2.stdout + p3.stdout + p.stderr)
    docker(home, 'rm', name)
    p = docker(home, 'run', '-d', *mode, '--name', name, '--stop-signal', 'SIGHUP', '-u', 'root', img,
               'trap "" HUP; while :; do sleep 0.2; done')
    time.sleep(0.5)
    began = time.time()
    p = docker(home, 'stop', '-t', '1', name)
    p2 = docker(home, 'inspect', '-f', '{{.State.ExitCode}}', name)
    check(p2.stdout.strip() == '137' and time.time() - began < 6, 'stop timeout then SIGKILL' + tag,
          p2.stdout + p.stderr)
    docker(home, 'rm', name)
    p = docker(home, 'run', '-d', *mode, '--name', name, '--restart', 'on-failure:2', img,
               'echo run; exit 1')
    p = docker(home, 'wait', name)
    time.sleep(0.5)
    logs = docker(home, 'logs', name).stdout
    check(p.stdout.strip() == '1' and logs.count('run') == 3, 'restart policy on-failure:2, wait' + tag,
          p.stdout + logs)
    docker(home, 'rm', '-f', name)
    # Named volume persistence.
    p = docker(home, 'run', '--rm', *mode, '-u', 'root', '-v', 'testvol:/v', img, 'echo kept > /v/f')
    p = docker(home, 'run', '--rm', *mode, '-v', 'testvol:/v', img, 'cat /v/f')
    check(p.stdout == 'kept\n', 'named volume persists' + tag, p.stdout + p.stderr)
    # --read-only: the image rootfs does not change; /tmp is writable.
    root = image_root(home, img)
    before = tree(root)
    p = docker(home, 'run', '--rm', *mode, '--read-only', '-u', 'root', img,
               'echo x > /etc/x 2>/dev/null || echo refused; echo t > /tmp/t && cat /tmp/t')
    check(p.stdout == 'refused\nt\n' and tree(root) == before, '--read-only' + tag, p.stdout + p.stderr)


DOCKERFILE = r'''# syntax=docker/dockerfile:1
ARG BASE=test/alpine:1
FROM ${BASE} AS builder
USER root
ARG GREETING=hello
WORKDIR /build
COPY src/ ./src/
COPY *.txt ./
RUN --mount=type=cache,target=/cache echo "$GREETING" > out.txt && echo run >> /cache/count \
 && cat /cache/count | wc -l > runs.txt
RUN ["/bin/sh", "-c", "echo json-form > json.txt"]
RUN <<EOF
echo heredoc > heredoc.txt
EOF
RUN --mount=type=secret,id=token cat /run/secrets/token > secret-seen.txt
RUN --mount=type=bind,source=src,target=/mnt/src cat /mnt/src/a > bind-seen.txt && echo x > /mnt/src/written

FROM ${BASE}
USER root
ENV APP_HOME=/opt/app \
    MODE="prod mode" \
    PATH=/usr/local/bin:$PATH
RUN rm /etc/motd
WORKDIR $APP_HOME
COPY --from=builder /build/ ./
COPY --chmod=0755 <<EOT /usr/local/bin/hello
#!/bin/sh
echo "hello from $MODE"
EOT
ADD archive.tar.gz /opt/extracted/
LABEL org.example.version=1.2 org.example.name="test app"
EXPOSE 8080 9090/udp
VOLUME /data
STOPSIGNAL SIGINT
HEALTHCHECK --interval=30s --retries=2 CMD hello
SHELL ["/bin/sh", "-c"]
ONBUILD RUN echo onbuild-ran > /onbuild.txt
USER nobody
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["hello"]
'''


def build_tests(home, work):
    ctx = work / 'ctx'
    (ctx / 'src').mkdir(parents=True)
    (ctx / 'src' / 'a').write_text('file a\n')
    (ctx / 'src' / 'ignored.log').write_text('no')
    (ctx / 'one.txt').write_text('1\n')
    (ctx / 'secret').write_text('s3cret')
    (ctx / '.dockerignore').write_text('**/*.log\nsecret\n')
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w:gz') as tar:
        info, data = member('inside/x', data=b'from tar')
        tar.addfile(info, io.BytesIO(data))
    (ctx / 'archive.tar.gz').write_bytes(raw.getvalue())
    (ctx / 'Dockerfile').write_text(DOCKERFILE)
    args = ['build', '-t', 'test/built:1', '--build-arg', 'GREETING=hi there',
            '--secret', f'id=token,src={ctx / "secret"}', str(ctx)]
    p = docker(home, *args, timeout=600)
    check(p.returncode == 0 and 'Successfully tagged test/built:1' in p.stdout, 'build: multi-stage Dockerfile',
          p.stdout[-1500:] + p.stderr[-1500:])
    if p.returncode:
        return
    p = docker(home, 'run', '--rm', 'test/built:1')
    check(p.stdout == 'hello from prod mode\n', 'build: ENTRYPOINT, CMD, ENV, COPY heredoc --chmod',
          p.stdout + p.stderr)
    p = docker(home, 'run', '--rm', 'test/built:1',
               'pwd; id -un; cat out.txt runs.txt json.txt heredoc.txt secret-seen.txt bind-seen.txt '
               'src/a one.txt /opt/extracted/inside/x; ls src; test -e /etc/motd || echo motd-gone')
    expected = ('/opt/app\nnobody\nhi there\n1\njson-form\nheredoc\ns3cretfile a\nfile a\n1\nfrom tara\n'
                'motd-gone\n')
    check(p.stdout == expected, 'build: WORKDIR, USER, ARG, RUN forms, secret/bind/cache mounts, '
          '.dockerignore, ADD tar, whiteout', p.stdout + p.stderr)
    check(not (ctx / 'src' / 'written').exists(), 'build: a bind mount does not write the context')
    p = docker(home, 'inspect', '-f', '{{json .Config}}', 'test/built:1')
    cfg = json.loads(p.stdout)
    check(cfg.get('Labels') == {'org.example.version': '1.2', 'org.example.name': 'test app'} and
          set(cfg.get('ExposedPorts', {})) == {'8080/tcp', '9090/udp'} and cfg.get('Volumes') == {'/data': {}} and
          cfg.get('StopSignal') == 'SIGINT' and cfg.get('Healthcheck', {}).get('Retries') == 2 and
          cfg.get('OnBuild') == ['RUN echo onbuild-ran > /onbuild.txt'],
          'build: LABEL, EXPOSE, VOLUME, STOPSIGNAL, HEALTHCHECK, ONBUILD in the config', cfg)
    first = docker(home, 'images', '-q', '--no-trunc', 'test/built').stdout.strip()
    p = docker(home, *args, timeout=600)
    again = docker(home, 'images', '-q', '--no-trunc', 'test/built').stdout.strip()
    check(p.stdout.count('Using cache') >= 8 and first == again, 'build: full cache hit gives the same image',
          p.stdout[-800:])
    (ctx / 'src' / 'a').write_text('changed\n')
    p = docker(home, *args, timeout=600)
    out = docker(home, 'run', '--rm', 'test/built:1', 'cat src/a runs.txt').stdout
    check(p.returncode == 0 and out == 'changed\n2\n', 'build: a changed source invalidates the cache; '
          'the cache mount persists', out + p.stderr[-500:])
    (ctx / 'Dockerfile.child').write_text('FROM test/built:1\nUSER root\nRUN cat /onbuild.txt\n')
    p = docker(home, 'build', '-f', str(ctx / 'Dockerfile.child'), '-t', 'test/child', str(ctx), timeout=600)
    check(p.returncode == 0 and 'onbuild-ran' in p.stdout, 'build: ONBUILD triggers run in a child build',
          p.stdout[-800:] + p.stderr[-500:])
    (ctx / 'Dockerfile.fail').write_text('FROM test/alpine:1\nRUN exit 3\n')
    p = docker(home, 'build', '-f', str(ctx / 'Dockerfile.fail'), str(ctx), timeout=600)
    check(p.returncode == 1 and 'returned a non-zero code: 3' in p.stderr, 'build: a failing RUN fails the build',
          p.stderr[-300:])
    # Export and re-import: the same diff_ids.
    p = docker(home, 'save', '-o', str(work / 'built.tar'), 'test/built:1')
    layers_before = docker(home, 'inspect', '-f', '{{json .RootFS.Layers}}', 'test/built:1').stdout
    docker(home, 'rmi', '-f', 'test/child')
    docker(home, 'rmi', '-f', 'test/built:1')
    p = docker(home, 'load', '-i', str(work / 'built.tar'))
    layers_after = docker(home, 'inspect', '-f', '{{json .RootFS.Layers}}', 'test/built:1').stdout
    check(p.returncode == 0 and layers_before == layers_after and layers_before.strip() != 'null',
          'build: saved image loads again with the same diff_ids', p.stderr)
    # commit and diff.
    docker(home, 'run', '--name', 'changer', '-u', 'root', 'test/alpine:1',
           'echo new > /root/new; rm /etc/hostname.orig 2>/dev/null; echo m >> /etc/profile; rm -r /media')
    p = docker(home, 'diff', 'changer')
    lines = set(p.stdout.splitlines())
    check({'A /root/new', 'C /etc/profile', 'D /media'} <= lines, 'diff: added, changed, deleted', p.stdout)
    p = docker(home, 'commit', '-c', 'CMD ["cat /root/new"]', '-m', 'msg', 'changer', 'test/committed:1')
    p2 = docker(home, 'run', '--rm', 'test/committed:1')
    p3 = docker(home, 'run', '--rm', 'test/committed:1', 'test -e /media || echo media-gone')
    check(p.returncode == 0 and p2.stdout == 'new\n' and p3.stdout == 'media-gone\n',
          'commit: changes and -c CMD in the new image', p.stderr + p2.stdout + p2.stderr + p3.stdout)
    docker(home, 'rm', 'changer')


def main():
    home = Path(os.environ.get('ELF_OCI_TEST_HOME', DEFAULT_HOME))
    if not home.parent.is_dir():
        home = Path(tempfile.mkdtemp(prefix='elf-oci-test-'))
    if home.exists():
        shutil.rmtree(home)
    with tempfile.TemporaryDirectory(prefix='oci-work-', dir=home.parent) as tmp:
        work = Path(tmp)
        unpack_tests(home, work)
        registry_tests(home, work)
        if lib.ALPINE.exists():
            alpine_image(home, work)
            for isolate in (False, True):
                run_tests(home, work, isolate)
            p = docker(home, 'run', '--in-place', '--name', 'inplace', 'test/alpine:1', 'true')
            p2 = docker(home, 'images', '--format', '{{.Repository}} {{.Dirty}}')
            check('test/alpine yes' in p2.stdout, '--in-place marks the image modified', p2.stdout)
            docker(home, 'rm', 'inplace')
            build_tests(home, work)
            mount_owner_tests(home, work)
            cow_tests(home, work)
        else:
            print('SKIP: container runs need', lib.ALPINE)
        p = docker(home, 'system', 'prune', '-af', '--volumes')
        p2 = docker(home, 'images', '-q')
        check(p.returncode == 0 and not p2.stdout.strip() and not list((home / 'containers').iterdir()),
              'system prune removes everything unused', p.stderr + p2.stdout)
    shutil.rmtree(home, ignore_errors=True)
    if failures:
        print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
        sys.exit(1)
    print('ALL PASS')


if __name__ == '__main__':
    main()
