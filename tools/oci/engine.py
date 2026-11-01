"""Docker Engine API subset (docs/OCI.md R7) on a UNIX socket.

`docker engine [-H unix:///path/docker.sock]` serves the API that SDKs and
tools use instead of the command line (docker-py, testcontainers, Docker
SDK for Go, devcontainer CLI): ping, version, info; images (list, inspect,
pull, tag, remove); containers (create, start, stop, restart, kill, wait,
remove, list, inspect, logs, attach, archive get/put/head); exec (create,
start, inspect); volumes; networks (container networks, network.py). Responses follow Engine API
1.43; streams use the multiplexed frame format unless the container has a
TTY, and hijack the connection when the client asks to upgrade.

Everything runs through the same store and runtime as the docker command;
the server is only a front end. The socket is created 0600 in the store
(default $ELF_OCI_HOME/docker.sock). Mounting it into a container lets that
container create any container and bind any host directory, so a container
run with --isolate (HostConfig.Isolate) may not bind it unless
ELF_OCI_ALLOW_ENGINE_SOCKET=1."""
import base64
import io
import json
import os
import re
import secrets
import shlex
import signal
import socket
import socketserver
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import fmt
import guestfs
import images
import runtime
import store as store_mod

API_VERSION = '1.43'
MIN_API_VERSION = '1.24'


class APIError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def cli():
    import docker_cli
    return docker_cli


def default_socket(st):
    return st.home / 'docker.sock'


SERVING = set()  # the socket(s) this process serves


def socket_guard(st, binds, isolate):
    """A --isolate container may not reach the engine socket (it could make
    any container, bind any host directory) unless explicitly allowed."""
    if not isolate or os.environ.get('ELF_OCI_ALLOW_ENGINE_SOCKET') == '1':
        return
    guarded = {os.path.realpath(default_socket(st))} | {os.path.realpath(p) for p in SERVING}
    host = os.environ.get('DOCKER_HOST', '')
    if host.startswith('unix://'):
        guarded.add(os.path.realpath(host[7:]))
    for src in binds:
        if src.startswith('/') and os.path.realpath(src) in guarded:
            raise store_mod.StoreError('binding the engine socket into an --isolate container is refused '
                                       '(set ELF_OCI_ALLOW_ENGINE_SOCKET=1 to allow it)')


def unix_time(text):
    t = fmt.parse_time(text) if text else None
    return int(t) if t else 0


def frame(stream, data):
    return bytes([stream, 0, 0, 0]) + len(data).to_bytes(4, 'big') + data


# ---------------------------------------------------------------- objects
def image_summary(st, image_id):
    info = st.image_info(image_id)
    tags = [f'{r}:{t}' for r, t in cli().image_names(st, image_id)]
    return {'Id': 'sha256:' + image_id, 'ParentId': '', 'RepoTags': tags or ['<none>:<none>'],
            'RepoDigests': info['info'].get('repo_digests', []),
            'Created': unix_time(info['config'].get('created')), 'Size': info['info'].get('size', 0),
            'SharedSize': -1, 'VirtualSize': info['info'].get('size', 0),
            'Labels': (info['config'].get('config') or {}).get('Labels') or {}, 'Containers': -1}


def ports_of(st, record):
    """NetworkSettings.Ports: what the running container's forwarders bound."""
    return cli().network_settings(st, record)['Ports']


def port_bindings(record):
    """HostConfig.PortBindings in the Engine's form."""
    out = {}
    import network
    for spec in record['HostConfig'].get('PortBindings') or []:
        try:
            parsed = network.parse_publish(spec)
        except Exception:
            continue
        for ip, hp, cp, proto in parsed:
            out.setdefault(f'{cp}/{proto}', []).append({'HostIp': '' if ip == '0.0.0.0' else ip,
                                                        'HostPort': str(hp) if hp else ''})
    return out


def container_summary(st, record):
    cfg, host = record['Config'], record['HostConfig']
    command = ' '.join(shlex.quote(c) for c in (cfg.get('Entrypoint') or []) + (cfg.get('Cmd') or []))
    ports = []
    for key, bindings in ports_of(st, record).items():
        port, _, proto = key.partition('/')
        for b in bindings or []:
            ports.append({'IP': b['HostIp'], 'PrivatePort': int(port), 'PublicPort': int(b['HostPort']),
                          'Type': proto})
    settings = cli().network_settings(st, record)
    return {'Id': record['Id'], 'Names': ['/' + record['Name']], 'Image': record['ImageName'],
            'ImageID': 'sha256:' + record['Image'], 'Command': command,
            'Created': unix_time(record['Created']), 'Ports': ports, 'Labels': cfg.get('Labels') or {},
            'State': record['State']['Status'], 'Status': cli().status_text(record),
            'HostConfig': {'NetworkMode': record['HostConfig'].get('NetworkMode') or 'host'},
            'NetworkSettings': {'Networks': settings['Networks']},
            'Mounts': [{'Type': 'bind' if s.startswith('/') else 'volume', 'Source': s, 'Destination': d,
                        'RW': m != 'ro'} for s, d, m in host['Binds']]}


def container_inspect(st, record):
    out = cli().container_inspect(st, record)
    out['HostConfig']['PortBindings'] = port_bindings(record)
    out['HostConfig'].setdefault('LogConfig', {'Type': 'json-file', 'Config': {}})
    out['HostConfig'].setdefault('Privileged', False)
    out['HostConfig'].setdefault('Mounts', [])
    out['Config'].setdefault('AttachStdin', False)
    out['Config'].setdefault('AttachStdout', True)
    out['Config'].setdefault('AttachStderr', True)
    out.setdefault('LogPath', str(st.container_dir(record['Id']) / 'log'))
    exposed = dict(out['Config'].get('ExposedPorts') or {})
    exposed.update({k: {} for k in out['HostConfig']['PortBindings']})
    out['Config']['ExposedPorts'] = exposed
    out['State']['Health'] = None
    out.pop('Health', None)
    return out


def matches(st, record, filters):
    labels = record['Config'].get('Labels') or {}
    for key, values in filters.items():
        values = list(values) if isinstance(values, (list, dict)) else [values]
        if key == 'label':
            for v in values:
                k, sep, val = v.partition('=')
                if k not in labels or (sep and labels[k] != val):
                    return False
        elif key == 'name':
            if not any(re.search(v.lstrip('/'), record['Name']) for v in values):
                return False
        elif key == 'id':
            if not any(record['Id'].startswith(v) for v in values):
                return False
        elif key == 'status':
            if record['State']['Status'] not in values:
                return False
        elif key in ('ancestor',):
            try:
                ids = {st.resolve_image(v) for v in values}
            except store_mod.StoreError:
                return False
            if record['Image'] not in ids:
                return False
    return True


# ---------------------------------------------------------------- create
def create_container(st, body, name=None):
    """POST /containers/create: the record made through the docker command's
    own path (validation, image config, runtime.create)."""
    c = cli()
    image = body.get('Image')
    if not image:
        raise APIError(400, 'Config cannot be empty in order to create a container')
    host = body.get('HostConfig') or {}
    warnings = []
    args = []
    if name:
        args += ['--name', name]
    if body.get('Hostname'):
        args += ['-h', body['Hostname']]
    for e in body.get('Env') or []:
        args += ['-e', e]
    if body.get('WorkingDir'):
        args += ['-w', body['WorkingDir']]
    if body.get('User'):
        args += ['-u', body['User']]
    if body.get('Tty'):
        args.append('-t')
    if body.get('OpenStdin'):
        args.append('-i')
    for k, v in (body.get('Labels') or {}).items():
        args += ['-l', f'{k}={v}']
    if body.get('StopSignal'):
        args += ['--stop-signal', body['StopSignal']]
    if body.get('StopTimeout') is not None:
        args += ['--stop-timeout', str(body['StopTimeout'])]
    binds = []
    for b in host.get('Binds') or []:
        args += ['-v', b]
        binds.append(b.split(':')[0])
    for m in host.get('Mounts') or []:
        kind, target = m.get('Type', 'volume'), m.get('Target')
        ro = ':ro' if m.get('ReadOnly') else ''
        if kind == 'tmpfs':
            args += ['--tmpfs', target]
        elif kind in ('bind', 'volume'):
            src = m.get('Source') or ''
            args += ['-v', f'{src}:{target}{ro}' if src else target]
            binds.append(src)
        else:
            raise APIError(400, f'mount type {kind} is not supported')
    for path in (host.get('Tmpfs') or {}):
        args += ['--tmpfs', path]
    for key, bindings in (host.get('PortBindings') or {}).items():
        port, _, proto = key.partition('/')
        for bnd in bindings or [{}]:
            bnd = bnd or {}
            hp, hip = str(bnd.get('HostPort') or ''), bnd.get('HostIp') or ''
            args += ['-p', (f'{hip}:' if hip else '') + (f'{hp}:' if hp or hip else '') + port +
                     (f'/{proto}' if proto and proto != 'tcp' else '')]
    if host.get('PublishAllPorts'):
        args.append('-P')
    policy = host.get('RestartPolicy') or {}
    if policy.get('Name'):
        name_ = policy['Name']
        if name_ == 'on-failure' and policy.get('MaximumRetryCount'):
            name_ += f':{policy["MaximumRetryCount"]}'
        args += ['--restart', name_]
    if host.get('AutoRemove'):
        args.append('--rm')
    if host.get('ReadonlyRootfs'):
        args.append('--read-only')
    for h in host.get('ExtraHosts') or []:
        args += ['--add-host', h.replace('=', ':', 1) if ':' not in h else h]
    for d in host.get('Dns') or []:
        args += ['--dns', d]
    mode = host.get('NetworkMode') or 'default'
    endpoints = (body.get('NetworkingConfig') or {}).get('EndpointsConfig') or {}
    if mode == 'default' and endpoints:
        mode = next(iter(endpoints))
    args += ['--network', mode]
    for alias in (endpoints.get(mode) or {}).get('Aliases') or []:
        args += ['--network-alias', alias]
    ipam = (endpoints.get(mode) or {}).get('IPAMConfig') or {}
    if ipam.get('IPv4Address'):
        args += ['--ip', ipam['IPv4Address']]
    if host.get('Privileged'):
        raise APIError(400, 'privileged containers need kernel privileges an app does not have')
    for key in ('CapAdd', 'Devices', 'Memory', 'NanoCpus', 'CpuShares', 'PidMode', 'IpcMode', 'Ulimits',
                'Sysctls', 'SecurityOpt', 'Init'):
        if host.get(key):
            warnings.append(f'{key} ignored: no namespaces or cgroups here')
    if host.get('Isolate'):
        args.append('--isolate')
    if host.get('Cow'):
        args.append('--cow')
    if host.get('Owners'):
        args.append('--owners')
    socket_guard(st, binds, host.get('Isolate'))
    try:
        image_id = st.resolve_image(image)
    except store_mod.StoreError:
        raise APIError(404, f'No such image: {image}')
    c.check_unsupported(args)
    try:
        a = c.run_parser('create').parse_args(args + [image])
    except c.Fail as e:
        raise APIError(400, str(e))
    a.command = []
    try:
        record = c.new_record(st, a, image_id, image)
    except c.Fail as e:
        raise APIError(400, str(e))
    cfg = record['Config']
    if 'Entrypoint' in body and body['Entrypoint'] is not None:
        ep = body['Entrypoint']
        cfg['Entrypoint'] = shlex.split(ep) if isinstance(ep, str) else list(ep)
        cfg['Cmd'] = None
    if body.get('Cmd') is not None:
        cmd = body['Cmd']
        cfg['Cmd'] = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    if body.get('ExposedPorts'):
        cfg['ExposedPorts'] = dict(body['ExposedPorts'])
    try:
        runtime.create(st, record)
    except store_mod.StoreError as e:
        raise APIError(409 if 'already in use' in str(e) else 500, str(e))
    return {'Id': record['Id'], 'Warnings': warnings}


# ---------------------------------------------------------------- exec instances
class Exec:
    def __init__(self, cid, body):
        self.id = secrets.token_hex(32)
        self.cid = cid
        self.cmd = body.get('Cmd') or []
        self.env = body.get('Env') or []
        self.user = body.get('User') or None
        self.workdir = body.get('WorkingDir') or None
        self.tty = bool(body.get('Tty'))
        self.stdin = bool(body.get('AttachStdin'))
        self.proc = None
        self.exit = None


EXECS = {}
EXECS_LOCK = threading.Lock()


# ---------------------------------------------------------------- HTTP
ROUTES = []


def route(method, pattern):
    def wrap(fn):
        ROUTES.append((method, re.compile('^' + pattern + '$'), fn))
        return fn
    return wrap


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'Docker/27.0.0-elf (linux)'
    st = None

    def log_message(self, fmt_, *args):
        if os.environ.get('ELF_ENGINE_LOG'):
            sys.stderr.write('engine: ' + (fmt_ % args) + '\n')

    def address_string(self):
        return 'unix'

    # ---- dispatch
    def handle_one(self, method):
        url = urllib.parse.urlsplit(self.path)
        path = re.sub(r'^/v[0-9.]+', '', url.path) or '/'
        self.query = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query, keep_blank_values=True).items()}
        self.qlist = urllib.parse.parse_qs(url.query, keep_blank_values=True)
        for m, pattern, fn in ROUTES:
            mm = pattern.match(path)
            if mm and (m == method or (m == 'GET' and method == 'HEAD' and fn.__name__ == 'ping')):
                try:
                    fn(self, *[urllib.parse.unquote(g) for g in mm.groups()])
                except APIError as e:
                    self.send_json(e.status, {'message': str(e)})
                except store_mod.StoreError as e:
                    msg = str(e)
                    status = 404 if 'No such' in msg or 'not found' in msg.lower() else \
                        409 if 'Conflict' in msg or 'in use' in msg or 'is running' in msg else 500
                    self.send_json(status, {'message': msg})
                except (BrokenPipeError, ConnectionResetError):
                    self.close_connection = True
                except Exception as e:  # noqa: BLE001  The client gets the error, the server lives.
                    self.send_json(500, {'message': f'{type(e).__name__}: {e}'})
                return
        self.send_json(404, {'message': f'page not found: {method} {path}'})

    def do_GET(self):
        self.handle_one('GET')

    def do_HEAD(self):
        self.handle_one('HEAD')

    def do_POST(self):
        self.handle_one('POST')

    def do_PUT(self):
        self.handle_one('PUT')

    def do_DELETE(self):
        self.handle_one('DELETE')

    # ---- bodies
    def body_bytes(self):
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            out = io.BytesIO()
            while True:
                size = int(self.rfile.readline().split(b';')[0].strip() or b'0', 16)
                if not size:
                    while self.rfile.readline() not in (b'\r\n', b'\n', b''):
                        pass
                    return out.getvalue()
                out.write(self.rfile.read(size))
                self.rfile.readline()
        length = int(self.headers.get('Content-Length') or 0)
        return self.rfile.read(length) if length else b''

    def body_json(self):
        data = self.body_bytes()
        if not data.strip():
            return {}
        try:
            return json.loads(data)
        except ValueError:
            raise APIError(400, 'invalid JSON body')

    # ---- responses
    def common_headers(self):
        self.send_header('Api-Version', API_VERSION)
        self.send_header('Docker-Experimental', 'false')
        self.send_header('Ostype', 'linux')
        self.send_header('Server', self.server_version)

    def send_json(self, status, obj, headers=None):
        data = (json.dumps(obj) + '\n').encode() if obj is not None else b''
        self.send_response(status)
        self.common_headers()
        if obj is not None:
            self.send_header('Content-Type', 'application/json')
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    def send_empty(self, status=204):
        self.send_response(status)
        self.common_headers()
        self.send_header('Content-Length', '0')
        self.end_headers()

    def start_stream(self, content_type, hijack=False):
        """A body delimited by closing the connection (or a hijacked raw stream)."""
        upgrade = hijack and 'upgrade' in self.headers.get('Connection', '').lower()
        if upgrade:
            self.send_response(101, 'UPGRADED')
            self.send_header('Content-Type', content_type)
            self.send_header('Connection', 'Upgrade')
            self.send_header('Upgrade', 'tcp')
        else:
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Connection', 'close')
        self.common_headers()
        self.end_headers()
        self.wfile.flush()
        self.close_connection = True

    def write(self, data):
        self.wfile.write(data)
        self.wfile.flush()

    def container(self, name):
        try:
            return runtime.refresh(self.st, self.st.resolve_container(name))
        except store_mod.StoreError:
            raise APIError(404, f'No such container: {name}')

    def flag(self, key, default=False):
        v = self.query.get(key)
        if v is None:
            return default
        return v.lower() in ('1', 'true', 'yes')


# ---- system
@route('GET', r'/_ping')
def ping(h):
    h.send_response(200)
    h.common_headers()
    h.send_header('Content-Type', 'text/plain; charset=utf-8')
    h.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
    h.send_header('Content-Length', '2')
    h.end_headers()
    if h.command != 'HEAD':
        h.wfile.write(b'OK')


@route('GET', r'/version')
def version(h):
    h.send_json(200, {'Version': '27.0.0-elf', 'ApiVersion': API_VERSION, 'MinAPIVersion': MIN_API_VERSION,
                      'Os': 'linux', 'Arch': 'arm64', 'KernelVersion': os.uname().release,
                      'GoVersion': 'n/a', 'GitCommit': 'elf', 'BuildTime': '',
                      'Platform': {'Name': 'ELF loader (docs/OCI.md)'},
                      'Components': [{'Name': 'Engine', 'Version': '27.0.0-elf',
                                      'Details': {'ApiVersion': API_VERSION, 'Os': 'linux', 'Arch': 'arm64'}}]})


@route('GET', r'/info')
def info(h):
    st = h.st
    recs = [runtime.refresh(st, c) for c in st.containers()]
    running = sum(1 for r in recs if r['State']['Status'] == 'running')
    h.send_json(200, {'ID': 'elf', 'Name': socket.gethostname(), 'ServerVersion': '27.0.0-elf',
                      'Containers': len(recs), 'ContainersRunning': running, 'ContainersPaused': 0,
                      'ContainersStopped': len(recs) - running, 'Images': len(st.images()),
                      'Driver': 'elf', 'DockerRootDir': str(st.home), 'OSType': 'linux',
                      'OperatingSystem': 'HarmonyOS (ELF loader)', 'Architecture': 'aarch64',
                      'KernelVersion': os.uname().release, 'NCPU': os.cpu_count() or 1, 'MemTotal': 0,
                      'Labels': [], 'ExperimentalBuild': False, 'Runtimes': {'elf': {'path': 'elfloader'}},
                      'DefaultRuntime': 'elf', 'SecurityOptions': [], 'Warnings': [
                          'no namespaces or cgroups: containers share the host network and PID space']})


# ---- images
@route('GET', r'/images/json')
def images_list(h):
    h.send_json(200, [image_summary(h.st, i) for i in h.st.images()])


@route('GET', r'/images/(.+)/json')
def image_inspect(h, name):
    try:
        image_id = h.st.resolve_image(name)
    except store_mod.StoreError:
        raise APIError(404, f'No such image: {name}')
    h.send_json(200, cli().image_inspect(h.st, image_id))


@route('POST', r'/images/create')
def image_create(h):
    ref = h.query.get('fromImage')
    if not ref:
        raise APIError(400, 'fromImage is required (import from source is not supported)')
    tag = h.query.get('tag')
    if tag and '@' not in ref and ':' not in ref.rsplit('/', 1)[-1]:
        ref = f'{ref}@{tag}' if tag.startswith('sha256:') else f'{ref}:{tag}'
    elif not tag and '@' not in ref and ':' not in ref.rsplit('/', 1)[-1]:
        ref += ':latest'
    h.start_stream('application/json')
    h.write(json.dumps({'status': f'Pulling from {ref}'}).encode() + b'\n')
    try:
        image_id = images.pull(h.st, ref, mirror=os.environ.get('ELF_OCI_MIRROR'), quiet=True)
        h.write(json.dumps({'status': f'Digest: sha256:{image_id}'}).encode() + b'\n')
        h.write(json.dumps({'status': f'Status: Downloaded newer image for {ref}'}).encode() + b'\n')
    except Exception as e:  # noqa: BLE001  Reported in the stream, as dockerd does.
        h.write(json.dumps({'errorDetail': {'message': str(e)}, 'error': str(e)}).encode() + b'\n')


@route('POST', r'/images/(.+)/tag')
def image_tag(h, name):
    repo, tag = h.query.get('repo'), h.query.get('tag') or 'latest'
    if not repo:
        raise APIError(400, 'repo is required')
    cli().cmd_tag(h.st, [name, f'{repo}:{tag}'])
    h.send_empty(201)


@route('DELETE', r'/images/(.+)')
def image_delete(h, name):
    try:
        image_id = h.st.resolve_image(name)
    except store_mod.StoreError:
        raise APIError(404, f'No such image: {name}')
    args = (['-f'] if h.flag('force') else []) + [name]
    try:
        cli().cmd_rmi(h.st, args)
    except cli().Fail as e:
        raise APIError(409, str(e))
    h.send_json(200, [{'Deleted': 'sha256:' + image_id}])


# ---- containers
@route('POST', r'/containers/create')
def containers_create(h):
    h.send_json(201, create_container(h.st, h.body_json(), h.query.get('name') or None))


@route('GET', r'/containers/json')
def containers_list(h):
    filters = json.loads(h.query.get('filters') or '{}')
    out = []
    for c in h.st.containers():
        c = runtime.refresh(h.st, c)
        if not h.flag('all') and c['State']['Status'] not in ('running', 'restarting') and 'status' not in filters:
            continue
        if matches(h.st, c, filters):
            out.append(container_summary(h.st, c))
    out.sort(key=lambda s: -s['Created'])
    limit = int(h.query.get('limit') or -1)
    h.send_json(200, out[:limit] if limit > 0 else out)


@route('GET', r'/containers/([^/]+)/json')
def container_json(h, name):
    h.send_json(200, container_inspect(h.st, h.container(name)))


@route('POST', r'/containers/([^/]+)/start')
def container_start(h, name):
    r = h.container(name)
    h.body_bytes()
    if r['State']['Status'] in ('running', 'restarting'):
        return h.send_empty(304)
    runtime.start_detached(h.st, r)
    h.send_empty(204)


@route('POST', r'/containers/([^/]+)/stop')
def container_stop(h, name):
    r = h.container(name)
    if r['State']['Status'] not in ('running', 'restarting'):
        return h.send_empty(304)
    t = h.query.get('t')
    runtime.stop(h.st, r, int(t) if t not in (None, '') else None,
                 runtime.parse_signal(h.query['signal']) if h.query.get('signal') else None)
    h.send_empty(204)


@route('POST', r'/containers/([^/]+)/restart')
def container_restart(h, name):
    r = h.container(name)
    t = h.query.get('t')
    if r['State']['Status'] in ('running', 'restarting'):
        runtime.stop(h.st, r, int(t) if t not in (None, '') else None)
    runtime.start_detached(h.st, h.st.load_container(r['Id']))
    h.send_empty(204)


@route('POST', r'/containers/([^/]+)/kill')
def container_kill(h, name):
    r = h.container(name)
    if r['State']['Status'] not in ('running', 'restarting'):
        raise APIError(409, f'Container {r["Id"]} is not running')
    runtime.kill(h.st, r, runtime.parse_signal(h.query.get('signal') or 'KILL'))
    h.send_empty(204)


@route('POST', r'/containers/([^/]+)/wait')
def container_wait(h, name):
    r = h.container(name)
    condition = h.query.get('condition') or 'not-running'
    # Headers first: clients wait for them before the long poll.
    h.send_response(200)
    h.common_headers()
    h.send_header('Content-Type', 'application/json')
    h.send_header('Connection', 'close')
    h.end_headers()
    h.wfile.flush()
    h.close_connection = True
    if condition == 'next-exit' and r['State']['Status'] not in ('running', 'restarting'):
        while runtime.refresh(h.st, h.st.load_container(r['Id']))['State']['Status'] not in \
                ('running', 'restarting'):
            time.sleep(0.2)
    code = runtime.wait(h.st, r)
    if condition == 'removed':
        while True:
            try:
                h.st.load_container(r['Id'])
            except store_mod.StoreError:
                break
            time.sleep(0.2)
    h.write(json.dumps({'StatusCode': code, 'Error': None}).encode() + b'\n')


@route('DELETE', r'/containers/([^/]+)')
def container_delete(h, name):
    r = h.container(name)
    if r['State']['Status'] in ('running', 'restarting') and not h.flag('force'):
        raise APIError(409, f'You cannot remove a running container {r["Id"]}. Stop the container before '
                       'attempting removal or force remove')
    args = (['-f'] if h.flag('force') else []) + (['-v'] if h.flag('v') else []) + [r['Id']]
    out = io.StringIO()
    old = sys.stdout
    sys.stdout = out
    try:
        code = cli().cmd_rm(h.st, args)
    finally:
        sys.stdout = old
    if code:
        raise APIError(500, f'could not remove {name}')
    h.send_empty(204)


@route('POST', r'/containers/([^/]+)/rename')
def container_rename(h, name):
    r = h.container(name)
    out = io.StringIO()
    old = sys.stdout
    sys.stdout = out
    try:
        cli().cmd_rename(h.st, [r['Id'], h.query.get('name', '')])
    except cli().Fail as e:
        raise APIError(409, str(e))
    finally:
        sys.stdout = old
    h.send_empty(204)


def stream_log(h, r, follow, tail, since=0):
    """The container's output (stdout and stderr were merged into one log)."""
    tty = r['Config'].get('Tty')
    path = h.st.container_dir(r['Id']) / 'log'

    def emit(data):
        if data:
            h.write(data if tty else frame(1, data))
    if not path.exists():
        if not follow:
            return
        while not path.exists():
            cur = runtime.refresh(h.st, h.st.load_container(r['Id']))
            if cur['State']['Status'] not in ('running', 'restarting', 'created'):
                return
            time.sleep(0.2)
    with open(path, 'rb') as f:
        data = f.read()
        if tail is not None:
            lines = data.splitlines(keepends=True)
            data = b''.join(lines[-tail:] if tail else [])
        emit(data)
        while follow:
            chunk = f.read(65536)
            if chunk:
                emit(chunk)
                continue
            cur = runtime.refresh(h.st, h.st.load_container(r['Id']))
            if cur['State']['Status'] not in ('running', 'restarting'):
                emit(f.read())
                return
            time.sleep(0.1)


@route('GET', r'/containers/([^/]+)/logs')
def container_logs(h, name):
    r = h.container(name)
    if not (h.flag('stdout') or h.flag('stderr')):
        raise APIError(400, 'Bad parameters: you must choose at least one stream')
    tail = h.query.get('tail')
    tail = None if tail in (None, '', 'all') else int(tail)
    h.start_stream('application/vnd.docker.raw-stream' if r['Config'].get('Tty') else
                   'application/vnd.docker.multiplexed-stream')
    stream_log(h, r, h.flag('follow'), tail)


@route('POST', r'/containers/([^/]+)/attach')
def container_attach(h, name):
    r = h.container(name)
    h.start_stream('application/vnd.docker.raw-stream' if r['Config'].get('Tty') else
                   'application/vnd.docker.multiplexed-stream', hijack=True)
    # Output only: the log (with logs=1 from the start, else what follows).
    if h.flag('stream'):
        if not h.flag('logs'):
            path = h.st.container_dir(r['Id']) / 'log'
            skip = path.stat().st_size if path.exists() else 0
            tty = r['Config'].get('Tty')
            while not path.exists():
                time.sleep(0.1)
            with open(path, 'rb') as f:
                f.seek(skip)
                while True:
                    chunk = f.read(65536)
                    if chunk:
                        h.write(chunk if tty else frame(1, chunk))
                        continue
                    cur = runtime.refresh(h.st, h.st.load_container(r['Id']))
                    if cur['State']['Status'] not in ('running', 'restarting', 'created'):
                        rest = f.read()
                        if rest:
                            h.write(rest if tty else frame(1, rest))
                        return
                    time.sleep(0.1)
        stream_log(h, r, True, None)
    elif h.flag('logs'):
        stream_log(h, r, False, None)


@route('GET', r'/containers/([^/]+)/top')
def container_top(h, name):
    r = h.container(name)
    pid = r['State'].get('Pid')
    procs = [[str(pid), ' '.join((r['Config'].get('Entrypoint') or []) + (r['Config'].get('Cmd') or []))]] \
        if pid else []
    h.send_json(200, {'Titles': ['PID', 'CMD'], 'Processes': procs})


def path_stat(host, name):
    st_ = os.lstat(host)
    mode = st_.st_mode & 0o777
    if os.path.isdir(host) and not os.path.islink(host):
        mode |= 1 << 31
    if os.path.islink(host):
        mode |= 1 << 27
    stat_json = {'name': name, 'size': st_.st_size, 'mode': mode,
                 'mtime': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(st_.st_mtime)),
                 'linkTarget': os.readlink(host) if os.path.islink(host) else ''}
    return base64.b64encode(json.dumps(stat_json).encode()).decode()


@route('HEAD', r'/containers/([^/]+)/archive')
def archive_head(h, name):
    archive(h, name)


@route('GET', r'/containers/([^/]+)/archive')
def archive(h, name):
    r = h.container(name)
    path = h.query.get('path')
    if not path:
        raise APIError(400, 'path is required')
    view = runtime.guest_view(h.st, r)
    parts = view.resolve(path, follow=True)
    host, present = view.host(parts, fill=True)
    if not present:
        raise APIError(404, f'Could not find the file {path} in container {name}')
    base = Path(path.rstrip('/')).name or '/'
    header = {'X-Docker-Container-Path-Stat': path_stat(host, base)}
    if h.command == 'HEAD':
        h.send_response(200)
        h.common_headers()
        for k, v in header.items():
            h.send_header(k, v)
        h.send_header('Content-Length', '0')
        h.end_headers()
        return
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.PAX_FORMAT) as tar:
        guestfs.copy(view.walk(parts, [base if base != '/' else '.']), guestfs.TarSink(tar))
    data = buf.getvalue()
    h.send_response(200)
    h.common_headers()
    h.send_header('Content-Type', 'application/x-tar')
    for k, v in header.items():
        h.send_header(k, v)
    h.send_header('Content-Length', str(len(data)))
    h.end_headers()
    h.wfile.write(data)


@route('PUT', r'/containers/([^/]+)/archive')
def archive_put(h, name):
    r = h.container(name)
    path = h.query.get('path')
    if not path:
        raise APIError(400, 'path is required')
    view = runtime.guest_view(h.st, r)
    parts = view.resolve(path, follow=True)
    if not view.is_dir(parts):
        raise APIError(404 if not view.exists(parts) else 400, f'destination {path} must be a directory')
    data = h.body_bytes()
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tar:
        guestfs.copy(guestfs.tar_walk(tar),
                     guestfs.DirSink(view.open_dir(parts), runtime.lower_of(h.st, r) is not None))
    h.send_empty(200)


# ---- exec
@route('POST', r'/containers/([^/]+)/exec')
def exec_create(h, name):
    r = h.container(name)
    if r['State']['Status'] != 'running':
        raise APIError(409, f'Container {r["Id"]} is not running')
    body = h.body_json()
    if not body.get('Cmd'):
        raise APIError(400, 'No exec command specified')
    e = Exec(r['Id'], body)
    with EXECS_LOCK:
        EXECS[e.id] = e
    h.send_json(201, {'Id': e.id})


def exec_of(eid):
    with EXECS_LOCK:
        e = EXECS.get(eid)
    if e is None:
        raise APIError(404, f'No such exec instance: {eid}')
    return e


@route('POST', r'/exec/([^/]+)/start')
def exec_start(h, eid):
    e = exec_of(eid)
    body = h.body_json()
    detach = bool(body.get('Detach'))
    tty = bool(body.get('Tty', e.tty))
    st = h.st
    record = runtime.refresh(st, st.load_container(e.cid))
    if record['State']['Status'] != 'running':
        raise APIError(409, f'Container {e.cid} is not running')
    argv, _ = runtime.command_line(st, record, extra_env=e.env, workdir=e.workdir, user=e.user,
                                   command=e.cmd)
    cwd = str(runtime.rootfs_of(st, record))
    if detach:
        e.proc = runtime.exec_spawn(st, e.cid, lambda: subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=cwd, start_new_session=True))

        def reap():
            e.exit = e.proc.wait()
            runtime.exec_done(st, e.cid, e.proc.pid)
        threading.Thread(target=reap, daemon=True).start()
        return h.send_empty(200)
    e.proc = runtime.exec_spawn(st, e.cid, lambda: subprocess.Popen(
        argv, stdin=subprocess.PIPE if e.stdin else subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if tty else subprocess.PIPE, cwd=cwd, start_new_session=True))
    h.start_stream('application/vnd.docker.raw-stream' if tty else 'application/vnd.docker.multiplexed-stream',
                   hijack=True)
    lock = threading.Lock()

    def pump(src, stream):
        while True:
            chunk = os.read(src.fileno(), 65536)
            if not chunk:
                return
            with lock:
                try:
                    h.write(chunk if tty else frame(stream, chunk))
                except OSError:
                    return
    readers = [threading.Thread(target=pump, args=(e.proc.stdout, 1), daemon=True)]
    if not tty:
        readers.append(threading.Thread(target=pump, args=(e.proc.stderr, 2), daemon=True))
    for t in readers:
        t.start()
    if e.stdin:
        def feed():
            try:
                while True:
                    chunk = h.rfile.read1(65536) if hasattr(h.rfile, 'read1') else h.rfile.read(1)
                    if not chunk:
                        break
                    e.proc.stdin.write(chunk)
                    e.proc.stdin.flush()
            except (OSError, ValueError):
                pass
            try:
                e.proc.stdin.close()
            except OSError:
                pass
        threading.Thread(target=feed, daemon=True).start()
    code = e.proc.wait()
    runtime.exec_done(st, e.cid, e.proc.pid)
    for t in readers:
        t.join(5)
    e.exit = 128 - code if code < 0 else code
    try:
        h.connection.shutdown(socket.SHUT_WR)
    except OSError:
        pass


@route('GET', r'/exec/([^/]+)/json')
def exec_json(h, eid):
    e = exec_of(eid)
    running = e.proc is not None and e.proc.poll() is None
    if e.proc is not None and not running and e.exit is None:
        code = e.proc.returncode
        e.exit = 128 - code if code < 0 else code
    h.send_json(200, {'ID': e.id, 'ContainerID': e.cid, 'Running': running,
                      'ExitCode': None if running or e.proc is None else e.exit,
                      'Pid': e.proc.pid if e.proc else 0, 'OpenStdin': e.stdin, 'OpenStdout': True,
                      'OpenStderr': True, 'CanRemove': False,
                      'ProcessConfig': {'tty': e.tty, 'entrypoint': e.cmd[0] if e.cmd else '',
                                        'arguments': e.cmd[1:], 'privileged': False, 'user': e.user or ''}})


@route('POST', r'/exec/([^/]+)/resize')
def exec_resize(h, eid):
    exec_of(eid)
    h.send_empty(201)


@route('POST', r'/containers/([^/]+)/resize')
def container_resize(h, name):
    h.container(name)
    h.send_empty(200)


# ---- volumes and networks
@route('GET', r'/volumes')
def volumes_list(h):
    out = []
    base = h.st.home / 'volumes'
    for d in sorted(base.iterdir()) if base.is_dir() else []:
        v = cli().volume_inspect(h.st, d.name)
        if v:
            out.append(v)
    h.send_json(200, {'Volumes': out, 'Warnings': []})


@route('POST', r'/volumes/create')
def volume_create(h):
    body = h.body_json()
    name = body.get('Name') or secrets.token_hex(32)
    h.st.create_volume(name, body.get('Labels') or {})
    h.send_json(201, cli().volume_inspect(h.st, name))


@route('GET', r'/volumes/([^/]+)')
def volume_get(h, name):
    v = cli().volume_inspect(h.st, name)
    if not v:
        raise APIError(404, f'get {name}: no such volume')
    h.send_json(200, v)


@route('DELETE', r'/volumes/([^/]+)')
def volume_delete(h, name):
    if not cli().volume_inspect(h.st, name):
        raise APIError(404, f'get {name}: no such volume')
    if cli().volume_users(h.st, name) and not h.flag('force'):
        raise APIError(409, f'remove {name}: volume is in use')
    store_mod.remove(h.st.volume_dir(name))
    h.send_empty(204)


def network_view(st, name):
    import network
    spec = network.inspect(st, name)
    spec['Id'] = spec['Id'] if len(spec['Id']) > 12 else spec['Id']
    return spec


@route('GET', r'/networks')
def networks_list(h):
    import network
    h.send_json(200, [network.inspect(h.st, n) for n in network.networks(h.st)])


@route('GET', r'/networks/([^/]+)')
def network_get(h, name):
    try:
        h.send_json(200, network_view(h.st, name))
    except store_mod.StoreError as e:
        raise APIError(404, str(e)) from None


@route('POST', r'/networks/create')
def network_create(h):
    import network
    body = h.body_json()
    try:
        spec = network.create(h.st, body.get('Name'), body.get('Driver') or 'bridge', body.get('Labels') or {},
                              body.get('Internal'), body.get('Attachable'), body.get('Options') or {},
                              check=body.get('CheckDuplicate', True))
    except store_mod.StoreError as e:
        raise APIError(409 if 'exists' in str(e) else 400, str(e)) from None
    h.send_json(201, {'Id': spec['Id'], 'Warning': ''})


@route('DELETE', r'/networks/([^/]+)')
def network_delete(h, name):
    import network
    try:
        network.remove(h.st, name)
    except store_mod.StoreError as e:
        raise APIError(404 if 'not found' in str(e) else 409, str(e)) from None
    h.send_empty(204)


@route('POST', r'/networks/([^/]+)/(connect|disconnect)')
def network_connect(h, name, action):
    import network
    body = h.body_json()
    try:
        record = h.st.resolve_container(body.get('Container') or '')
        if action == 'connect':
            aliases = ((body.get('EndpointConfig') or {}).get('Aliases')) or []
            network.connect(h.st, record, name, aliases)
        else:
            network.disconnect(h.st, record, name)
    except store_mod.StoreError as e:
        raise APIError(404 if 'not found' in str(e) or 'No such' in str(e) else 400, str(e)) from None
    h.send_empty(200)


# ---------------------------------------------------------------- server
class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(st, address=None, ready=None):
    path = Path(address or default_socket(st))
    if path.exists() or path.is_symlink():
        probe = socket.socket(socket.AF_UNIX)
        try:
            probe.connect(str(path))
            raise store_mod.StoreError(f'an engine is already listening on {path}')
        except (ConnectionRefusedError, FileNotFoundError):
            path.unlink()
        finally:
            probe.close()
    path.parent.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o177)
    try:
        server = Server(str(path), type('BoundHandler', (Handler,), {'st': st}))
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    SERVING.add(str(path))

    def stop(signum, frame):
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f'API listen on {path}', file=sys.stderr, flush=True)
    if ready:
        ready()
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        try:
            path.unlink()
        except OSError:
            pass
    return 0


def main(st, argv):
    c = cli()
    p = c.parser('engine', 'Serve the Docker Engine API on a UNIX socket (ELF, docs/OCI.md R7)')
    p.add_argument('-H', '--host', help='unix:///path/to/docker.sock (default: $ELF_OCI_HOME/docker.sock)')
    a = p.parse_args(argv)
    address = None
    if a.host:
        if not a.host.startswith('unix://'):
            raise c.Fail('only unix:// sockets are supported (a TCP socket would serve the API to the network)')
        address = a.host[7:]
    return serve(st, address)
