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
import base64
import gzip
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
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


def docker(home, *args, input=None, timeout=300, env=None, text=True):
    return subprocess.run([sys.executable, '-B', str(DOCKER), *args], capture_output=True, text=text,
                          input=input, timeout=timeout,
                          env=dict(os.environ, ELF_OCI_HOME=str(home), **(env or {})))


def group_members(pgid):
    out = []
    for entry in os.listdir('/proc'):
        if entry.isdigit():
            try:
                if int(Path(f'/proc/{entry}/stat').read_text().rsplit(')', 1)[1].split()[2]) == pgid:
                    out.append(int(entry))
            except OSError:
                pass
    return out


def proc_start(pid):
    try:
        return int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
    except OSError:
        return None


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
    # Never '' (that would name the working directory).
    assert p.returncode == 0 and p.stdout.strip(), (name, p.stdout, p.stderr)
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
        # A directory comes out merged: the upper's and the lower's files,
        # without the whited-out ones or whiteout markers (also as tar).
        out = work / ('cow-etc' + tag)
        p = docker(home, 'cp', f'{name}:/etc', str(out))
        p2 = docker(home, 'cp', f'{name}:/etc', '-', text=False)
        names = set(tarfile.open(fileobj=io.BytesIO(p2.stdout)).getnames()) if p2.returncode == 0 else set()
        check(p.returncode == 0 and (out / 'motd').read_text() == 'changed\n' and (out / 'fstab').exists() and
              (out / 'alpine-release').exists() and not (out / 'issue').exists() and
              not any(n.startswith('.wh.') for _, ds, fs in os.walk(out) for n in ds + fs) and
              {'etc/motd', 'etc/fstab', 'etc/alpine-release'} <= names and 'etc/issue' not in names and
              not any('.wh.' in n for n in names),
              '--cow: cp of a directory is the merged view (whiteouts applied, markers hidden)' + tag,
              p.stderr + str(sorted(names))[:800])
        # A tar without entries for its directories: a directory the upper
        # deleted comes back opaque (only the new file shows).
        (cdir / 'upper/etc/.wh.apk').touch()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            info = tarfile.TarInfo('etc/apk/new')
            info.size = 4
            tar.addfile(info, io.BytesIO(b'new\n'))
        p = docker(home, 'cp', '-', f'{name}:/', input=buf.getvalue(), text=False)
        out = work / ('cow-apk' + tag)
        p2 = docker(home, 'cp', f'{name}:/etc/apk', str(out))
        check(p.returncode == 0 and p2.returncode == 0 and sorted(os.listdir(out)) == ['new'],
              '--cow: cp of a tar without directory entries keeps a deleted directory deleted' + tag,
              [p.stderr, p2.stderr, sorted(os.listdir(out)) if out.exists() else None])
        # A symlink in the upper at the destination is replaced, not followed.
        victim = work / ('cow-victim' + tag)
        victim.write_text('host\n')
        (cdir / 'upper/usr/share/cow-in').unlink()
        os.symlink(victim, cdir / 'upper/usr/share/cow-in')
        p = docker(home, 'cp', str(work / 'cow-in'), f'{name}:/usr/share/')
        check(p.returncode == 0 and victim.read_text() == 'host\n' and
              not (cdir / 'upper/usr/share/cow-in').is_symlink() and
              (cdir / 'upper/usr/share/cow-in').read_text() == 'in\n',
              '--cow: cp into the upper replaces a symlink at the destination' + tag, p.stderr)
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


def erofs_tests(home, work):
    """R6 layer images: docker image erofs; --cow runs on them (docs/OCI.md)."""
    sys.path.insert(0, str(lib.REPO / 'tools/oci'))
    import erofs
    ctx = work / 'erofs-ctx'
    ctx.mkdir()
    lines = ['FROM test/alpine:1', 'USER root', 'WORKDIR /']
    lines += [f'RUN echo layer{i} > /srv/l{i}' for i in range(9)]
    lines += ['RUN rm /srv/l0 /etc/motd && rm -r /etc/apk/protected_paths.d && mkdir /etc/apk/protected_paths.d '
              '&& echo opq > /etc/apk/protected_paths.d/x',
              'RUN chown 321:654 /srv/l1 && chmod 4750 /srv/l1']
    (ctx / 'Dockerfile').write_text('\n'.join(lines) + '\n')
    img = 'test/layers:1'
    p = docker(home, 'build', '-q', '-t', img, str(ctx), timeout=900)
    check(p.returncode == 0, 'layer images: a 12-layer image builds', p.stderr[-800:])
    if p.returncode:
        return
    cmd = ('cat /srv/l*; ls /etc/apk/protected_paths.d; test -e /etc/motd || echo motd-gone; '
           'stat -c "%u %g %a" /srv/l1; cat /etc/alpine-release; apk --version | cut -c1-9')
    ref = docker(home, 'run', '--rm', '--owners', img, cmd)
    p = docker(home, 'image', 'erofs', img, 'test/alpine:1')
    data = json.loads(docker(home, 'inspect', '-f', '{{json .GraphDriver.Data}}', img).stdout)
    stack = data.get('LayerImages', '').split(':')
    check(p.returncode == 0 and len(stack) == 8 and 'chain-' in stack[-1] and
          all(Path(i).exists() for i in stack), 'docker image erofs: 12 layers as 7 layer images and one '
          'of the bottom chain (the loader takes 8 lowers)', p.stdout + p.stderr + str(data))
    images_before = {i: sha(Path(i).read_bytes()) for i in (home / 'layers').glob('*.erofs')}
    for mode in ([], ['--isolate']):
        tag = ' (--isolate)' if mode else ''
        p = docker(home, 'run', '--rm', '--cow', '--owners', *mode, img, cmd)
        check(ref.returncode == 0 and p.returncode == 0 and p.stdout == ref.stdout and '321 654 4750' in p.stdout,
              '--cow on layer images: the same view as a copy (layers, whiteouts, opaque, owners)' + tag,
              ref.stdout + '\n---\n' + p.stdout + p.stderr)
    held = sum(1 for c in (home / 'layers').glob('*.cache') for d, _, fs in os.walk(c) for f in fs
               if erofs.placeholder(os.lstat(os.path.join(d, f))))
    check(held > 0 and {i: sha(Path(i).read_bytes()) for i in (home / 'layers').glob('*.erofs')} == images_before,
          'layer images: expanded on demand (unread files stay placeholders); the images unchanged', held)
    name = 'erofs-c'
    p = docker(home, 'run', '--cow', '--name', name, img, 'echo w > /srv/l2 && rm /srv/l3 && cat /srv/l2')
    cid = docker(home, 'inspect', '-f', '{{.Id}}', name).stdout.strip()
    cdir = home / 'containers' / cid
    check(p.stdout == 'w\n' and (cdir / 'upper/srv/l2').read_text() == 'w\n' and (cdir / 'upper/srv/.wh.l3').exists(),
          'layer images: writes go to the upper', p.stdout + p.stderr)
    p = docker(home, 'diff', name)
    check({'C /srv/l2', 'D /srv/l3'} <= set(p.stdout.splitlines()) and 'A /srv/l4' not in p.stdout,
          'layer images: diff (the lower scanned from the images)', p.stdout + p.stderr)
    p = docker(home, 'cp', f'{name}:/srv/l4', str(work / 'erofs-out'))
    check(p.returncode == 0 and (work / 'erofs-out').read_text() == 'layer4\n', 'layer images: cp out',
          p.stderr)
    # A file nothing read yet is a placeholder in its cache: cp fills it first.
    held = [Path(d, 'x') for c in (home / 'layers').glob('*.cache')
            for d, _, fs in os.walk(c) if d.endswith('etc/apk/protected_paths.d') and 'x' in fs]
    unread = [h for h in held if erofs.placeholder(os.lstat(h))]
    p = docker(home, 'cp', f'{name}:/etc/apk/protected_paths.d/x', str(work / 'erofs-x'))
    p2 = docker(home, 'cp', f'{name}:/srv', str(work / 'erofs-srv'))
    srv = sorted(os.listdir(work / 'erofs-srv')) if p2.returncode == 0 else []
    check(unread and p.returncode == 0 and (work / 'erofs-x').read_text() == 'opq\n' and
          srv == ['l1', 'l2', 'l4', 'l5', 'l6', 'l7', 'l8'] and (work / 'erofs-srv/l2').read_text() == 'w\n' and
          (work / 'erofs-srv/l8').read_text() == 'layer8\n',
          'layer images: cp fills unread files; a directory is the merged view', [held, srv, p.stderr, p2.stderr])
    p = docker(home, 'commit', name, 'test/erofs-commit:1')
    p2 = docker(home, 'run', '--rm', 'test/erofs-commit:1', 'cat /srv/l2; test -e /srv/l3 || echo gone')
    check(p.returncode == 0 and p2.stdout == 'w\ngone\n', 'layer images: commit', p.stderr + p2.stdout + p2.stderr)
    docker(home, 'rm', name)
    docker(home, 'rmi', '-f', 'test/erofs-commit:1')
    # --prune: no unpacked rootfs; --cow needs none, a copy unpacks it again.
    image_id = docker(home, 'inspect', '-f', '{{.Id}}', img).stdout.strip()[7:]
    unpacked = home / 'images' / image_id / 'rootfs'
    p = docker(home, 'image', 'erofs', '--prune', img)
    shown = docker(home, 'inspect', '-f', '{{.GraphDriver.Data.Rootfs}}', img).stdout.strip()
    gone = not unpacked.exists() and shown == ''
    p2 = docker(home, 'run', '--rm', '--cow', img, 'cat /srv/l5')
    p3 = docker(home, 'run', '--rm', img, 'cat /srv/l6')
    check(p.returncode == 0 and gone and p2.stdout == 'layer5\n' and p3.stdout == 'layer6\n' and
          unpacked.exists(), 'docker image erofs --prune: --cow runs without the unpacked rootfs, '
          'a copy unpacks it again', p.stdout + p.stderr + p2.stdout + p2.stderr + p3.stdout + p3.stderr)
    docker(home, 'rmi', '-f', img)
    left = {Path(i).name for i in stack} & {p.name for p in (home / 'layers').iterdir()}
    check(not left, 'rmi removes the layer images no other image uses', left)


def compose_tests(home, work):
    """R7: docker compose (docs/OCI.md)."""
    proj = work / 'compose-proj'
    (proj / 'web').mkdir(parents=True)
    (proj / 'web' / 'Dockerfile').write_text('FROM test/alpine:1\nUSER root\nRUN echo built > /built\n')
    (proj / 'token.txt').write_text('tok\n')
    (proj / '.env').write_text('GREETING=hello # a comment\nPORT=18431\n')
    # The test image's entrypoint is ["/bin/sh", "-c"]: commands are one string.
    (proj / 'compose.yaml').write_text("""
name: ElfC
x-common: &common
  image: test/alpine:1
  user: root
services:
  db:
    <<: *common
    command: ["sleep 1; touch /tmp/ready; while true; do printf 'HTTP/1.0 200 OK\\r\\n\\r\\ndb-page\\n' | nc -l -p ${PORT}; done"]
    healthcheck:
      test: ["CMD", "test", "-f", "/tmp/ready"]
      interval: 1s
      retries: 20
  web:
    build: ./web
    user: root
    depends_on:
      db: {condition: service_healthy}
    environment:
      - GREETING=${GREETING:-unset}
    secrets: [token]
    command: ["cat /built /run/secrets/token; wget -qO- http://db:${PORT}/; echo $$GREETING; exec sleep 60"]
  init:
    <<: *common
    command: ["echo seeded > /data/seed"]
    volumes: [data:/data]
  after:
    <<: *common
    depends_on:
      init: {condition: service_completed_successfully}
    command: ["cat /data/seed"]
    volumes: [data:/data]
  tool:
    <<: *common
    profiles: [tools]
volumes:
  data:
secrets:
  token:
    file: ./token.txt
""")

    def compose(*args, timeout=300):
        return docker(home, 'compose', '--project-directory', str(proj), '-f', str(proj / 'compose.yaml'),
                      *args, timeout=timeout)
    p = compose('up', '-d')
    check(p.returncode == 0, 'compose: up -d (build, healthy and completed dependencies)', p.stdout + p.stderr)
    time.sleep(2)
    p = compose('ps', '-a', '--format', '{{.Service}} {{.State}}')
    states = dict(line.split() for line in p.stdout.splitlines() if line.strip())
    check(states == {'db': 'running', 'web': 'running', 'init': 'exited', 'after': 'exited'},
          'compose: ps (the tools profile stays off)', p.stdout + p.stderr)
    p = compose('logs', 'web', 'after')
    shown = [re.sub(r' +\| ', ' | ', line) for line in p.stdout.splitlines()]
    check({'elfc-web-1 | built', 'elfc-web-1 | tok', 'elfc-web-1 | db-page', 'elfc-web-1 | hello',
           'elfc-after-1 | seeded'} <= set(shown),
          'compose: build, secrets, .env interpolation, a service reached by name, named volume',
          p.stdout + p.stderr)
    p = compose('exec', '-T', 'db', 'cat', '/tmp/ready')
    check(p.returncode == 0, 'compose: exec', p.stderr)
    p = compose('run', '--rm', '-T', '--no-deps', 'after', 'cat /data/seed; exit 4')
    check(p.returncode == 4 and p.stdout == 'seeded\n', 'compose: run --rm (exit status)', p.stdout + p.stderr)
    before = docker(home, 'inspect', '-f', '{{.Id}}', 'elfc-db-1').stdout
    p = compose('up', '-d', 'db')
    check(p.returncode == 0 and docker(home, 'inspect', '-f', '{{.Id}}', 'elfc-db-1').stdout == before,
          'compose: up keeps an unchanged service', p.stderr)
    (proj / 'compose.override.yaml').write_text('services:\n  db:\n    environment: [CHANGED=1]\n')
    p = docker(home, 'compose', '--project-directory', str(proj), 'up', '-d', 'db', timeout=300)
    check(p.returncode == 0 and docker(home, 'inspect', '-f', '{{.Id}}', 'elfc-db-1').stdout != before and
          'Recreate' in p.stderr, 'compose: a changed service is recreated (override file)', p.stderr)
    (proj / 'compose.override.yaml').unlink()
    p = compose('down', '-v')
    p2 = docker(home, 'ps', '-a', '--filter', 'label=com.docker.compose.project=elfc', '-q')
    check(p.returncode == 0 and not p2.stdout.strip() and not (home / 'volumes' / 'elfc_data').exists(),
          'compose: down -v', p.stderr + p2.stdout)
    # Foreground: prefixed output, the exit code of one service.
    fg = work / 'compose-fg'
    fg.mkdir()
    (fg / 'docker-compose.yml').write_text(
        'services:\n  a:\n    image: test/alpine:1\n    command: ["echo from-a; sleep 30"]\n'
        '  b:\n    image: test/alpine:1\n    command: ["sleep 1; echo from-b; exit 3"]\n')
    p = docker(home, 'compose', '--project-directory', str(fg), 'up', '--exit-code-from', 'b', timeout=120)
    check(p.returncode == 3 and 'compose-fg-a-1  | from-a' in p.stdout and 'compose-fg-b-1  | from-b' in p.stdout,
          'compose: foreground up, prefixed output, --exit-code-from', p.stdout + p.stderr)
    docker(home, 'compose', '--project-directory', str(fg), 'down')


def serve(text, port=80):
    """A test/alpine:1 command: an HTTP server answering text on port."""
    return (f'while true; do printf "HTTP/1.0 200 OK\\r\\n\\r\\n{text}\\n" | nc -l -p {port}; done')


def fetch(url, tries=20):
    """A shell snippet: GET url (retried while the server restarts nc)."""
    return f'for i in $(seq {tries}); do wget -qO- -T 2 {url} 2>/dev/null && break; sleep 0.3; done'


def http_get(port, timeout=20):
    import urllib.request
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=3) as r:
                return r.read().decode().strip()
        except OSError:
            time.sleep(0.3)
    return None


def network_tests(home, work):
    """Container networks and replicas (docs/OCI.md, network.py)."""
    img = 'test/alpine:1'
    p = docker(home, 'network', 'create', 'appnet')
    check(p.returncode == 0 and len(p.stdout.strip()) == 64, 'network create', p.stderr)
    for name in ('s1', 's2'):
        p = docker(home, 'run', '-d', '--name', name, '--network', 'appnet', '--network-alias', name + '-alias',
                   '-u', 'root', img, serve(name))
        check(p.returncode == 0, f'run -d {name} on a user-defined network (port 80)', p.stderr)
    ip1 = docker(home, 'inspect', '-f', '{{.NetworkSettings.IPAddress}}', 's1').stdout.strip()
    ip2 = docker(home, 'inspect', '-f', '{{.NetworkSettings.IPAddress}}', 's2').stdout.strip()
    check(ip1.startswith('127.') and ip2.startswith('127.') and ip1 != ip2,
          'each container has a loopback address of its own', (ip1, ip2))
    p = docker(home, 'run', '--rm', '--network', 'appnet', img,
               f'{fetch("http://s1/")}; {fetch("http://s2-alias/")}; {fetch("http://" + ip1 + "/")}')
    check(p.returncode == 0 and p.stdout.split() == ['s1', 's2', 's1'],
          'two containers listen on port 80; reached by name, alias and address', p.stdout + p.stderr)
    p = docker(home, 'run', '--rm', img, f'wget -qO- -T 2 http://{ip1}/ || echo refused; '
               'grep -c s1 /etc/hosts || true')
    check(p.stdout.split() == ['refused', '0'],
          'a container on another network neither reaches nor resolves it', p.stdout + p.stderr)
    p = docker(home, 'run', '--rm', '--isolate', img, f'wget -qO- -T 2 http://{ip1}/ || echo refused')
    check(p.stdout.split() == ['refused'], 'the same refusal under --isolate (broker)', p.stdout + p.stderr)
    p = docker(home, 'run', '-d', '--name', 'roamer', '-u', 'root', img, 'sleep 60')
    p = docker(home, 'network', 'connect', '--alias', 'rm-alias', 'appnet', 'roamer')
    p2 = docker(home, 'exec', 'roamer', 'sh', '-c', fetch('http://s1/'))
    check(p.returncode == 0 and p2.stdout.strip() == 's1', 'network connect: reaches the network by name',
          p.stderr + p2.stdout + p2.stderr)
    p = docker(home, 'network', 'disconnect', 'appnet', 'roamer')
    p2 = docker(home, 'exec', 'roamer', 'sh', '-c', f'wget -qO- -T 2 http://{ip1}/ || echo refused')
    check(p.returncode == 0 and p2.stdout.strip() == 'refused', 'network disconnect', p.stderr + p2.stdout)
    # Published ports: the forwarder of the container's process.
    p = docker(home, 'run', '-d', '--name', 'pub', '-p', '18480:80', '-u', 'root', img, serve('pub'))
    got = http_get(18480)
    p2 = docker(home, 'port', 'pub')
    p3 = docker(home, 'ps', '--filter', 'name=pub', '--format', '{{.Ports}}')
    check(p.returncode == 0 and got == 'pub' and p2.stdout.strip() == '80/tcp -> 0.0.0.0:18480' and
          p3.stdout.strip() == '0.0.0.0:18480->80/tcp', '-p 18480:80 forwards to the container (port, ps)',
          (got, p2.stdout, p3.stdout, p.stderr))
    p = docker(home, 'network', 'rm', 'appnet')
    check(p.returncode != 0 and 'active endpoints' in p.stderr, 'network rm of a network in use fails', p.stderr)
    docker(home, 'rm', '-f', 's1', 's2', 'roamer', 'pub')
    p = docker(home, 'network', 'rm', 'appnet')
    p2 = docker(home, 'network', 'ls', '--format', '{{.Name}}')
    check(p.returncode == 0 and p2.stdout.split() == ['bridge', 'host', 'none'], 'network rm, ls',
          p.stderr + p2.stdout)
    # Compose: networks, aliases, replicas, ports.
    proj = work / 'compose-net'
    proj.mkdir()
    (proj / 'compose.yaml').write_text(f"""
name: netp
x-base: &base
  image: {img}
  user: root
services:
  web:
    <<: *base
    command: ['{serve('web-$$HOSTNAME')}']
    deploy:
      replicas: 2
    networks: [front]
  api:
    <<: *base
    command: ['{serve('api')}']
    ports: ["18481:80"]
    networks:
      front:
      back:
        aliases: [api-internal]
  db:
    <<: *base
    command: ['{serve('db')}']
    networks: [back]
  ui:
    <<: *base
    command: ['sleep 60']
    networks: [front]
networks:
  front:
  back:
""")

    def compose(*args, timeout=300):
        return docker(home, 'compose', '--project-directory', str(proj), *args, timeout=timeout)
    p = compose('up', '-d')
    check(p.returncode == 0 and 'Network netp_front  Created' in p.stderr and 'netp-web-2' in p.stderr,
          'compose: networks created, replicas started', p.stderr)
    p = compose('exec', '-T', 'ui', 'sh', '-c',
                f'{fetch("http://netp-web-1/")}; {fetch("http://netp-web-2/")}; {fetch("http://api/")}; '
                'wget -qO- -T 2 http://db/ || echo no-db; grep -c " web" /etc/hosts')
    out = p.stdout.split()
    check(len(out) == 5 and out[0].startswith('web-') and out[1].startswith('web-') and out[0] != out[1] and
          out[2:] == ['api', 'no-db', '2'],
          'compose: replicas on port 80 each, a service in two networks, db unreachable from front',
          p.stdout + p.stderr)
    p = compose('exec', '-T', 'db', 'sh', '-c', fetch('http://api-internal/'))
    check(p.stdout.strip() == 'api', 'compose: a network alias', p.stdout + p.stderr)
    check(http_get(18481) == 'api', 'compose: ports forward to the service')
    p = compose('up', '-d', '--scale', 'web=3', 'web')
    p2 = compose('ps', '--format', '{{.Name}}')
    check(p.returncode == 0 and 'netp-web-3' in p2.stdout.split(), 'compose: up --scale web=3', p.stderr + p2.stdout)
    p = compose('scale', 'web=1')
    p2 = compose('ps', '--format', '{{.Name}}')
    names = p2.stdout.split()
    check(p.returncode == 0 and 'netp-web-1' in names and 'netp-web-2' not in names and 'netp-web-3' not in names,
          'compose: scale web=1 removes the others', p.stderr + p2.stdout)
    p = compose('down')
    p2 = docker(home, 'network', 'ls', '--format', '{{.Name}}')
    check(p.returncode == 0 and 'netp_front' not in p2.stdout, 'compose: down removes the networks',
          p.stderr + p2.stdout)


def engine_tests(home, work):
    """R7: the Engine API on a UNIX socket (docs/OCI.md)."""
    import http.client
    import socket as socket_mod
    sock = work / 'engine.sock'
    server = subprocess.Popen([sys.executable, '-B', str(DOCKER), 'engine', '-H', f'unix://{sock}'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                              env=dict(os.environ, ELF_OCI_HOME=str(home)))
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.1)

    class Conn(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket_mod.socket(socket_mod.AF_UNIX)
            self.sock.connect(str(sock))

    def api(method, url, body=None, raw=None, headers=None):
        c = Conn('localhost', timeout=120)
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        hdrs = dict(headers or {})
        if body is not None:
            hdrs['Content-Type'] = 'application/json'
        c.request(method, '/v1.43' + url, body=data, headers=hdrs)
        r = c.getresponse()
        out = r.read()
        c.close()
        return r.status, out, r

    def js(out):
        return json.loads(out) if out.strip() else None

    def demux(data):
        streams = {1: b'', 2: b''}
        while len(data) >= 8:
            n = int.from_bytes(data[4:8], 'big')
            streams[data[0]] = streams.get(data[0], b'') + data[8:8 + n]
            data = data[8 + n:]
        return streams
    try:
        status, out, r = api('GET', '/_ping')
        st2, ver, _ = api('GET', '/version')
        st3, inf, _ = api('GET', '/info')
        check(status == 200 and out == b'OK' and r.getheader('Api-Version') == '1.43' and
              js(ver)['ApiVersion'] == '1.43' and st3 == 200 and 'Containers' in js(inf),
              'engine: ping, version, info', str(out) + str(ver))
        status, out, _ = api('GET', '/images/json')
        check(status == 200 and any('test/alpine:1' in i['RepoTags'] for i in js(out)),
              'engine: images/json', out[:300])
        status, out, _ = api('POST', '/containers/create?name=api1',
                             {'Image': 'test/alpine:1', 'Cmd': ['echo out; echo err >&2; exit 3'],
                              'Labels': {'elf.test': 'api'}})
        cid = (js(out) or {}).get('Id', '')
        s1, _, _ = api('POST', f'/containers/{cid}/start')
        s2, waited, _ = api('POST', f'/containers/{cid}/wait')
        s3, logs, r = api('GET', f'/containers/{cid}/logs?stdout=1&stderr=1')
        check(status == 201 and s1 == 204 and s2 == 200 and js(waited)['StatusCode'] == 3 and s3 == 200 and
              demux(logs)[1] == b'out\nerr\n' and 'multiplexed' in (r.getheader('Content-Type') or ''),
              'engine: create, start, wait, logs (multiplexed frames)', str(out) + str(waited) + str(logs))
        status, out, _ = api('GET', '/containers/json?all=1&filters=' +
                             urllib.parse.quote(json.dumps({'label': ['elf.test=api']})))
        check(status == 200 and [c['Names'] for c in js(out)] == [['/api1']] and js(out)[0]['State'] == 'exited',
              'engine: containers/json with a label filter', out[:300])
        status, out, _ = api('GET', '/containers/api1/json')
        check(status == 200 and js(out)['State']['ExitCode'] == 3 and js(out)['Name'] == '/api1',
              'engine: containers/{id}/json', out[:300])
        status, out, _ = api('POST', '/containers/create?name=api2',
                             {'Image': 'test/alpine:1', 'Cmd': ['sleep 60'],
                              'HostConfig': {'PortBindings': {'18432/tcp': [{'HostPort': ''}]}}})
        api('POST', '/containers/api2/start')
        s1, out, _ = api('POST', '/containers/api2/exec', {'Cmd': ['sh', '-c', 'echo hi; echo oops >&2; exit 5'],
                                                           'AttachStdout': True, 'AttachStderr': True})
        eid = (js(out) or {}).get('Id', '')
        s2, out, _ = api('POST', f'/exec/{eid}/start', {'Detach': False, 'Tty': False})
        s3, ex, _ = api('GET', f'/exec/{eid}/json')
        frames = demux(out)
        check(s1 == 201 and s2 == 200 and frames[1] == b'hi\n' and frames[2] == b'oops\n' and
              js(ex)['ExitCode'] == 5,
              'engine: exec create, start (stdout and stderr frames), inspect', str(out) + str(ex))
        status, out, _ = api('GET', '/containers/api2/json')
        bound = js(out)['NetworkSettings']['Ports'].get('18432/tcp') or [{}]
        check(len(bound) == 1 and bound[0].get('HostIp') == '0.0.0.0' and bound[0].get('HostPort', '0').isdigit() and
              int(bound[0]['HostPort']) > 0,
              'engine: a port binding without a host port gets a free host port', out[:400])
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            info = tarfile.TarInfo('put.txt')
            info.size = 4
            tar.addfile(info, io.BytesIO(b'put\n'))
        s1, _, _ = api('PUT', '/containers/api2/archive?path=/tmp', raw=buf.getvalue(),
                       headers={'Content-Type': 'application/x-tar'})
        s2, out, r = api('GET', '/containers/api2/archive?path=/tmp/put.txt')
        got = b''
        if s2 == 200:
            with tarfile.open(fileobj=io.BytesIO(out)) as tar:
                got = tar.extractfile('put.txt').read()
        stat = json.loads(base64.b64decode(r.getheader('X-Docker-Container-Path-Stat') or 'e30='))
        check(s1 == 200 and got == b'put\n' and stat.get('size') == 4, 'engine: archive put and get',
              f'{s1} {s2} {got} {stat}')
        s1, _, _ = api('POST', '/containers/api2/stop?t=1')
        s2, _, _ = api('DELETE', '/containers/api2')
        s3, _, _ = api('DELETE', f'/containers/{cid}')
        s4, _, _ = api('GET', '/containers/api1/json')
        check((s1, s2, s3, s4) == (204, 204, 204, 404), 'engine: stop, delete, 404 after', f'{s1} {s2} {s3} {s4}')
        s1, out, _ = api('POST', '/volumes/create', {'Name': 'apivol'})
        s2, lst, _ = api('GET', '/volumes')
        s3, _, _ = api('DELETE', '/volumes/apivol')
        check(s1 == 201 and 'apivol' in [v['Name'] for v in js(lst)['Volumes']] and s3 == 204,
              'engine: volumes', str(out) + str(lst))
        s1, out, _ = api('POST', '/networks/create', {'Name': 'n'})
        s2, out2, _ = api('POST', '/containers/create', {'Image': 'test/alpine:1',
                                                          'HostConfig': {'Privileged': True}})
        s3, out3, _ = api('POST', '/containers/create', {
            'Image': 'test/alpine:1', 'HostConfig': {'Isolate': True, 'Binds': [f'{sock}:/var/run/docker.sock']}})
        s4, _, _ = api('DELETE', '/networks/n')
        check(s1 == 201 and s4 == 204 and s2 == 400 and s3 >= 400 and b'refused' in out3,
              'engine: network create and delete; --privileged and the socket in an --isolate container refused',
              f'{s1} {s2} {s3} {out3}')
        p = docker(home, 'run', '--rm', '--isolate', '-v', f'{home}/docker.sock:/var/run/docker.sock',
                   'test/alpine:1', 'true')
        check(p.returncode == 125 and 'refused' in p.stderr, 'docker run --isolate with the engine socket refused',
              p.stderr)
    finally:
        server.terminate()
        try:
            server.wait(10)
        except subprocess.TimeoutExpired:
            server.kill()
    check(not sock.exists(), 'engine: the socket is removed on exit', server.stderr.read()[-500:])


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
    for flag in (['--privileged'], ['--memory', '1g'], ['--mac-address', '02:42:ac:11:00:02']):
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
    suffix = '-iso' if isolate else ''
    # A symlink the container placed at the destination (the final name, or a
    # directory inside a recursive copy) is replaced, never followed to the host.
    victim, victim_dir = work / ('victim' + suffix), work / ('victim-dir' + suffix)
    victim.write_text('host file\n')
    victim_dir.mkdir()
    (work / 'cptree' / 'sub').mkdir(parents=True, exist_ok=True)  # (both runs)
    (work / 'cptree' / 'sub' / 'f').write_text('tree\n')
    docker(home, 'exec', name, 'sh', '-c', f'mkdir -p /root/dest /root/tree && ln -s {victim} /root/dest/cpfile && '
           f'ln -s {victim_dir} /root/tree/sub')
    p = docker(home, 'cp', str(work / 'cpfile'), f'{name}:/root/dest')
    p2 = docker(home, 'cp', str(work / 'cptree') + '/.', f'{name}:/root/tree')
    p3 = docker(home, 'exec', name, 'sh', '-c', 'cat /root/dest/cpfile; echo; test -L /root/dest/cpfile || echo file; '
                'cat /root/tree/sub/f')
    check(p.returncode == 0 and p2.returncode == 0 and victim.read_text() == 'host file\n' and
          not any(victim_dir.iterdir()) and p3.stdout == 'copied\nfile\ntree\n',
          'cp into the container replaces its symlinks, never follows them to the host' + tag,
          p.stderr + p2.stderr + p3.stdout + p3.stderr)
    # A volume inside the copied tree gets its part (as the container sees
    # it); a read-only volume refuses.
    mvol, rovol = work / ('mvol' + suffix), work / ('rovol' + suffix)
    mvol.mkdir()
    rovol.mkdir()
    conf, roconf = work / ('app.conf' + suffix), work / ('ro.conf' + suffix)
    conf.write_text('old\n')
    roconf.write_text('old\n')
    mname = 'mnt' + suffix
    docker(home, 'run', *mode, '--name', mname, '-u', 'root', '-v', f'{mvol}:/srv/sub', '-v', f'{rovol}:/srv/ro:ro',
           '-v', f'{conf}:/srv/app.conf', '-v', f'{roconf}:/srv/ro.conf:ro', img, 'true')
    mcdir = home / 'containers' / docker(home, 'inspect', '-f', '{{.Id}}', mname).stdout.strip()
    p = docker(home, 'cp', str(work / 'cptree') + '/.', f'{mname}:/srv')
    p2 = docker(home, 'cp', str(work / 'cpfile'), f'{mname}:/srv/ro/')
    check(p.returncode == 0 and (mvol / 'f').read_text() == 'tree\n' and
          not (mcdir / 'rootfs/srv/sub/f').exists() and p2.returncode != 0 and not any(rovol.iterdir()),
          'cp into the container writes a volume inside the tree to its source; a read-only volume refuses' + tag,
          p.stderr + p2.stderr)
    # A file bind: cp updates its content through the source (the mount
    # stays); a read-only one refuses.
    p = docker(home, 'cp', str(work / 'cpfile'), f'{mname}:/srv/app.conf')
    p2 = docker(home, 'cp', str(work / 'cpfile'), f'{mname}:/srv/ro.conf')
    check(p.returncode == 0 and conf.read_text() == 'copied' and p2.returncode != 0 and
          roconf.read_text() == 'old\n', 'cp onto a file bind updates its source; a read-only one refuses' + tag,
          p.stderr + p2.stderr)
    # The bind's own source (also through a path alias), or a volume file
    # copied onto itself, keeps its content.
    alias = work / ('alias' + suffix)
    alias.symlink_to(work)
    (mvol / 'g').write_text('volfile\n')
    p = docker(home, 'cp', str(conf), f'{mname}:/srv/app.conf')
    p2 = docker(home, 'cp', str(alias / conf.name), f'{mname}:/srv/app.conf')
    p3 = docker(home, 'cp', str(alias / mvol.name / 'g'), f'{mname}:/srv/sub/')
    check(p.returncode == 0 and p2.returncode == 0 and p3.returncode == 0 and conf.read_text() == 'copied' and
          (mvol / 'g').read_text() == 'volfile\n',
          'cp of a bind source onto itself (or through an alias) keeps its content' + tag,
          p.stderr + p2.stderr + p3.stderr)
    # --read-only: a writable file bind in a read-only directory updates; the
    # root's own files still refuse.
    rname = 'rofile' + suffix
    docker(home, 'run', *mode, '--name', rname, '--read-only', '-v', f'{conf}:/etc/app.conf', img, 'true')
    rcdir = image_root(home, img)
    p = docker(home, 'cp', str(work / 'release'), f'{rname}:/etc/app.conf')
    p2 = docker(home, 'cp', str(work / 'cpfile'), f'{rname}:/etc/motd')
    check(p.returncode == 0 and conf.read_text() == (work / 'release').read_text() and p2.returncode != 0 and
          (rcdir / 'etc/motd').read_text() != 'copied',
          '--read-only: cp updates a writable file bind, the root refuses' + tag, p.stderr + p2.stderr)
    docker(home, 'rm', rname)
    docker(home, 'rm', mname)
    # exec -d processes are the container's: they end when it stops, also
    # background jobs left by an exec whose shell has exited.
    cdir = home / 'containers' / docker(home, 'inspect', '-f', '{{.Id}}', name).stdout.strip()
    p = docker(home, 'exec', '-d', name, 'sh', '-c', 'while :; do sleep 0.2; done')
    p = docker(home, 'exec', '-d', name, 'sh', '-c', 'sleep 300 & exit 0')
    time.sleep(1)
    execs = json.loads((cdir / 'execs.json').read_text()) if (cdir / 'execs.json').exists() else []
    left_behind = [pid for pid, _ in execs if proc_start(pid) is None and group_members(pid)]
    p = docker(home, 'stop', name)          # StopSignal SIGUSR1 from the image.
    p2 = docker(home, 'inspect', '-f', '{{.State.Status}} {{.State.ExitCode}}', name)
    p3 = docker(home, 'logs', name)
    check(p2.stdout.strip() == 'exited 9' and 'started' in p3.stdout and 'got-usr1' in p3.stdout,
          'stop sends the StopSignal; logs kept' + tag, p2.stdout + p3.stdout + p.stderr)
    time.sleep(0.3)
    check(len(execs) == 2 and len(left_behind) == 1 and
          not any(group_members(pid) for pid, start in execs) and not (cdir / 'execs.json').exists(),
          'exec -d processes and the background jobs they leave end with the container' + tag,
          [execs, left_behind])
    p = docker(home, 'exec', '-d', name, 'true')
    check(p.returncode != 0, 'no exec in a stopped container' + tag, p.stderr)
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


def saved_layers(home, image, work):
    """[{path: TarInfo}] of every layer of a saved image."""
    archive = work / 'layers-save.tar'
    p = docker(home, 'save', '-o', str(archive), image)
    assert p.returncode == 0, p.stderr
    out = []
    with tarfile.open(archive) as outer:
        manifest = json.load(outer.extractfile('manifest.json'))
        for name in manifest[0]['Layers']:
            blob = outer.extractfile(name).read()
            if blob[:2] == b'\x1f\x8b':
                blob = gzip.decompress(blob)
            with tarfile.open(fileobj=io.BytesIO(blob)) as layer:
                out.append({m.name.rstrip('/'): m for m in layer})
    archive.unlink()
    return out


def upper_build_tests(home, work, ctx):
    """R6: RUN writes an upper over the stage rootfs; the upper is the layer."""
    (ctx / 'Dockerfile.upper').write_text(
        'FROM test/alpine:1\nUSER root\nWORKDIR /\n'
        'RUN rm -r /media && mkdir -p /srv/old && echo a > /srv/a && echo keep > /etc/keep\n'
        'RUN rm -r /srv && mkdir /srv && echo b > /srv/b && chown 123:45 /srv/b && chmod 4755 /srv/b\n'
        'COPY one.txt /srv/\n'
        'RUN cat /srv/one.txt /srv/b > /srv/c && rm /etc/keep\n'
        'RUN true\n')
    p = docker(home, 'build', '-q', '-f', str(ctx / 'Dockerfile.upper'), '-t', 'test/upper:1', str(ctx),
               timeout=600)
    check(p.returncode == 0, 'build (upper): builds', p.stdout[-800:] + p.stderr[-800:])
    if p.returncode:
        return
    p = docker(home, 'run', '--rm', 'test/upper:1',
               'ls /srv; cat /srv/c; test -e /media || echo media-gone; test -e /etc/keep || echo keep-gone')
    check(p.stdout == 'b\nc\none.txt\n1\nb\nmedia-gone\nkeep-gone\n', 'build (upper): merged result',
          p.stdout + p.stderr)
    found = saved_layers(home, 'test/upper:1', work)
    base = len(found) - 4  # RUN, RUN, COPY, RUN; WORKDIR / exists (RUN true makes no layer)
    l1, l2, l3, l4 = found[base:]
    check('.wh.media' in l1 and 'srv/a' in l1 and 'srv/old' in l1 and 'etc/keep' in l1 and
          not any(k.startswith('bin/') for k in l1),
          'build (upper): RUN layer = the upper (whiteout, new files, nothing untouched)', sorted(l1))
    b = l2.get('srv/b')
    check('srv/.wh..wh..opq' in l2 and b is not None and (b.uid, b.gid) == (123, 45) and b.mode & 0o4000 and
          'srv/a' not in l2, 'build (upper): rm -r then mkdir gives an opaque directory; chown, setuid kept',
          {k: (v.uid, v.gid, oct(v.mode)) for k, v in l2.items()})
    check(set(l3) == {'srv', 'srv/one.txt'}, 'build (upper): COPY after RUN (snapshot kept current)', sorted(l3))
    check(set(l4) == {'srv', 'srv/c', 'etc', 'etc/.wh.keep'}, 'build (upper): RUN after COPY', sorted(l4))
    docker(home, 'rmi', '-f', 'test/upper:1')


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
    upper_build_tests(home, work, ctx)
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
            erofs_tests(home, work)
            compose_tests(home, work)
            network_tests(home, work)
            engine_tests(home, work)
        else:
            print('SKIP: container runs need', lib.ALPINE)
        p = docker(home, 'system', 'prune', '-af', '--volumes')
        p2 = docker(home, 'images', '-q')
        check(p.returncode == 0 and not p2.stdout.strip() and not list((home / 'containers').iterdir()) and
              (not (home / 'layers').exists() or not list((home / 'layers').iterdir())),
              'system prune removes everything unused', p.stderr + p2.stdout)
    shutil.rmtree(home, ignore_errors=True)
    if failures:
        print(f'{len(failures)} FAILED:', *failures, sep='\n  ')
        sys.exit(1)
    print('ALL PASS')


if __name__ == '__main__':
    main()
