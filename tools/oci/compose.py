"""docker compose (docs/OCI.md R7): compose files run as plain containers.

Every service becomes a container made through the same path as `docker
create` ({project}-{service}-1, labelled com.docker.compose.*), started by
its monitor process like `docker run -d`. There is no network of our own:
containers share the host network, so services reach each other at
localhost:<port>, and every service name resolves to 127.0.0.1 through the
containers' /etc/hosts. Two services cannot listen on the same port.

Supported: compose.yaml/compose.yml/docker-compose.y(a)ml (+ override,
several -f), .env and --env-file, ${VAR} interpolation (:- - :? ? :+ +, $$),
name/-p/COMPOSE_PROJECT_NAME, profiles, image, build (context, dockerfile,
args, target), command, entrypoint, environment, env_file, volumes (short
and long; named volumes are project volumes), tmpfs, ports (as themselves),
working_dir, user, hostname, container_name, depends_on (service_started,
service_healthy, service_completed_successfully), healthcheck, restart,
labels, extra_hosts, dns, stop_signal, stop_grace_period, read_only, tty,
stdin_open, secrets and configs (files), and x-elf: {isolate, cow, owners}.
Options that need namespaces or cgroups (networks, cap_add, mem_limit,
deploy.resources, init...) are ignored with a warning."""
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import runtime
import store as store_mod
import yamlite

FILES = ('compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml')
OVERRIDES = ('compose.override.yaml', 'compose.override.yml', 'docker-compose.override.yml',
             'docker-compose.override.yaml')
LABEL = 'com.docker.compose.'
IGNORED = ('networks', 'cap_add', 'cap_drop', 'privileged', 'mem_limit', 'memswap_limit', 'cpus',
           'cpu_shares', 'cpuset', 'pids_limit', 'ulimits', 'sysctls', 'devices', 'security_opt',
           'init', 'ipc', 'pid', 'shm_size', 'logging', 'deploy', 'mac_address', 'domainname',
           'oom_score_adj', 'oom_kill_disable', 'userns_mode', 'cgroup_parent', 'runtime',
           'platform', 'expose', 'links', 'external_links', 'scale', 'network_mode', 'group_add',
           'storage_opt', 'isolation', 'blkio_config', 'device_cgroup_rules', 'cgroup', 'uts',
           'pull_policy', 'annotations', 'attach', 'develop', 'post_start', 'pre_stop',
           'stop_signal_timeout', 'mem_reservation', 'mem_swappiness', 'cpu_quota', 'cpu_period',
           'credential_spec', 'use_api_socket', 'gpus', 'models', 'provider', 'label_file', 'volumes_from')


class ComposeError(Exception):
    pass


def warn(message):
    print(f'WARN[0000] {message}', file=sys.stderr)


# ---------------------------------------------------------------- loading
def parse_env_text(text):
    """KEY=VALUE lines of a .env file (export prefix, quotes, comments)."""
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        key, sep, value = line.partition('=')
        key = key.strip()
        if not sep or not key:
            continue
        value = value.strip()
        if value[:1] in '"\'' and len(value) >= 2 and value.endswith(value[0]):
            q, value = value[0], value[1:-1]
            if q == '"':
                value = value.encode().decode('unicode_escape') if '\\' in value else value
        else:
            value = re.sub(r'\s+#.*$', '', value)
        out[key] = value
    return out


_VAR = re.compile(r'\$(?:(\$)|\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))')


def interpolate(text, env, where=''):
    def one(m):
        if m.group(1):
            return '$'
        if m.group(3):
            return env.get(m.group(3), '')
        body = m.group(2)
        mm = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])(.*))?$', body, re.S)
        if not mm:
            raise ComposeError(f'invalid interpolation format for {where}: "${{{body}}}"')
        name, op, arg = mm.group(1), mm.group(2), mm.group(3) or ''
        arg = interpolate(arg, env, where) if op else arg
        value = env.get(name)
        unset = value is None
        empty = unset or value == ''
        if op == ':-':
            return arg if empty else value
        if op == '-':
            return arg if unset else value
        if op == ':?':
            if empty:
                raise ComposeError(f'required variable {name} is missing a value: {arg}')
            return value
        if op == '?':
            if unset:
                raise ComposeError(f'required variable {name} is missing a value: {arg}')
            return value
        if op == ':+':
            return '' if empty else arg
        if op == '+':
            return '' if unset else arg
        return value or ''
    return _VAR.sub(one, text)


def interpolate_tree(value, env, where=''):
    if isinstance(value, str):
        return interpolate(value, env, where)
    if isinstance(value, list):
        return [interpolate_tree(v, env, where) for v in value]
    if isinstance(value, dict):
        return {k: interpolate_tree(v, env, f'{where}.{k}' if where else str(k)) for k, v in value.items()}
    return value


def merge(base, extra):
    """Override files: mappings merge, most sequences replace (ports, volumes,
    expose... append, as compose does), scalars replace."""
    if isinstance(base, dict) and isinstance(extra, dict):
        out = dict(base)
        for k, v in extra.items():
            if k in out and isinstance(out[k], list) and isinstance(v, list) and \
                    k in ('ports', 'volumes', 'expose', 'extra_hosts', 'dns', 'env_file', 'secrets',
                          'configs', 'tmpfs', 'labels'):
                out[k] = out[k] + [x for x in v if x not in out[k]]
            elif k in out:
                out[k] = merge(out[k], v)
            else:
                out[k] = v
        return out
    return extra


def duration(text, default=None):
    """'1m30s', '10s', '500ms', 10 -> seconds."""
    if text is None:
        return default
    if isinstance(text, (int, float)):
        return float(text)
    total, found = 0.0, False
    for number, unit in re.findall(r'([0-9.]+)\s*(h|ms|m|s|us|ns)?', str(text)):
        found = True
        total += float(number) * {'h': 3600, 'm': 60, 's': 1, 'ms': 0.001, 'us': 1e-6, 'ns': 1e-9,
                                  None: 1, '': 1}[unit or '']
    if not found:
        raise ComposeError(f'invalid duration {text}')
    return total


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def key_values(value, sep='='):
    """environment/labels/extra_hosts/args as a list or a mapping -> {k: v or None}."""
    out = {}
    if isinstance(value, dict):
        for k, v in value.items():
            out[str(k)] = None if v is None else (str(v).lower() if isinstance(v, bool) else str(v))
    else:
        for item in as_list(value):
            item = str(item)
            if sep in item:
                k, _, v = item.partition(sep)
                out[k] = v
            elif sep == '=' :
                out[item] = None
            else:
                out[item] = None
    return out


class Project:
    def __init__(self, files=(), project_dir=None, name=None, env_files=(), profiles=()):
        self.files = [Path(f).resolve() for f in files]
        if not self.files:
            here = Path(project_dir).resolve() if project_dir else Path.cwd()
            while True:
                found = next((here / f for f in FILES if (here / f).is_file()), None)
                if found or here.parent == here:
                    break
                here = here.parent
            if not found:
                raise ComposeError('no configuration file provided: not found')
            self.files = [found]
            override = next((found.parent / f for f in OVERRIDES if (found.parent / f).is_file()), None)
            if override:
                self.files.append(override)
        self.dir = Path(project_dir).resolve() if project_dir else self.files[0].parent
        self.env = dict(os.environ)
        dotenv = {}
        for path in (env_files or [self.dir / '.env']):
            path = Path(path)
            if path.is_file():
                dotenv.update(parse_env_text(path.read_text()))
            elif env_files:
                raise ComposeError(f"couldn't find env file: {path}")
        for k, v in dotenv.items():
            self.env.setdefault(k, v)
        data = {}
        for f in self.files:
            loaded = yamlite.load(f.read_text()) or {}
            if not isinstance(loaded, dict):
                raise ComposeError(f'{f}: the top level must be a mapping')
            data = merge(data, loaded)
        data = interpolate_tree(data, self.env)
        self.data = data
        raw = name or self.env.get('COMPOSE_PROJECT_NAME') or data.get('name') or self.dir.name
        self.name = re.sub(r'[^a-z0-9_-]', '', str(raw).lower()).lstrip('_-')
        if not self.name:
            raise ComposeError(f'project name "{raw}" must contain a letter or digit')
        self.profiles = set(profiles) | {p for p in self.env.get('COMPOSE_PROFILES', '').split(',') if p}
        services = data.get('services') or {}
        if not isinstance(services, dict) or not services:
            raise ComposeError('no services defined')
        self.services = {}
        for sname, svc in services.items():
            svc = svc or {}
            if 'extends' in svc:
                svc = self.extend(sname, svc, services)
            self.services[str(sname)] = svc
        for sname, svc in self.services.items():
            if 'image' not in svc and 'build' not in svc:
                raise ComposeError(f'service "{sname}" has neither an image nor a build context specified')
        self.volumes = data.get('volumes') or {}
        self.secrets = data.get('secrets') or {}
        self.configs = data.get('configs') or {}

    def extend(self, name, svc, services):
        ext = svc['extends']
        ext = {'service': ext} if isinstance(ext, str) else ext
        if 'file' in ext:
            base = (yamlite.load((self.dir / ext['file']).read_text()) or {}).get('services', {})
            base = interpolate_tree(base, self.env)
        else:
            base = services
        parent = dict(base.get(ext['service']) or {})
        if 'extends' in parent:
            parent = self.extend(ext['service'], parent, base)
        rest = {k: v for k, v in svc.items() if k != 'extends'}
        return merge(parent, rest)

    def active(self, names=()):
        """Services to act on: those named (all their dependencies too), else
        every service whose profiles are enabled."""
        if names:
            for n in names:
                if n not in self.services:
                    raise ComposeError(f'no such service: {n}')
            out, todo = [], list(names)
            while todo:
                n = todo.pop()
                if n in out:
                    continue
                out.append(n)
                todo.extend(self.depends(n))
            return self.order(out)
        return self.order([n for n, s in self.services.items()
                           if not s.get('profiles') or set(as_list(s['profiles'])) & self.profiles])

    def depends(self, name):
        dep = self.services[name].get('depends_on') or []
        if isinstance(dep, dict):
            return [d for d, spec in dep.items() if (spec or {}).get('required', True) is not False or
                    d in self.services]
        return list(dep)

    def conditions(self, name):
        dep = self.services[name].get('depends_on') or []
        if isinstance(dep, dict):
            return {d: (spec or {}).get('condition', 'service_started') for d, spec in dep.items()}
        return {d: 'service_started' for d in dep}

    def order(self, names):
        """Dependencies first (cycles refused)."""
        out, state = [], {}

        def visit(n, path):
            if state.get(n) == 2:
                return
            if state.get(n) == 1:
                raise ComposeError(f'dependency cycle detected: {" -> ".join(path + [n])}')
            state[n] = 1
            for d in self.depends(n):
                if d not in self.services:
                    raise ComposeError(f'service "{n}" depends on undefined service "{d}"')
                visit(d, path + [n])
            state[n] = 2
            out.append(n)
        for n in names:
            visit(n, [])
        return [n for n in out if n in names or any(n in self.depends(m) for m in names)]

    def container_name(self, name, number=1):
        return self.services[name].get('container_name') or f'{self.name}-{name}-{number}'

    def image_name(self, name):
        svc = self.services[name]
        return svc.get('image') or f'{self.name}-{name}'

    def volume_name(self, name):
        spec = self.volumes.get(name) or {}
        if spec.get('name'):
            return spec['name']
        if spec.get('external'):
            return name
        return f'{self.name}_{name}'

    def path(self, text):
        text = os.path.expanduser(str(text))
        return str((self.dir / text).resolve()) if not text.startswith('/') else text


# ---------------------------------------------------------------- service -> docker create
def command_list(value):
    if value is None:
        return None
    return [str(v) for v in value] if isinstance(value, list) else shlex.split(str(value))


def healthcheck(project, name, image_config):
    """(test argv or None, interval, timeout, retries, start_period)."""
    hc = project.services[name].get('healthcheck')
    if hc is None:
        img = image_config.get('Healthcheck') or {}
        hc = {'test': img.get('Test'), 'interval': (img.get('Interval') or 0) / 1e9 or None,
              'timeout': (img.get('Timeout') or 0) / 1e9 or None, 'retries': img.get('Retries'),
              'start_period': (img.get('StartPeriod') or 0) / 1e9 or None}
    if hc.get('disable'):
        return None
    test = hc.get('test')
    if not test or test == ['NONE']:
        return None
    if isinstance(test, str):
        argv = ['/bin/sh', '-c', test]
    elif test[0] == 'CMD':
        argv = [str(t) for t in test[1:]]
    elif test[0] == 'CMD-SHELL':
        argv = ['/bin/sh', '-c', ' '.join(str(t) for t in test[1:])]
    else:
        argv = [str(t) for t in test]
    return (argv, duration(hc.get('interval'), 30.0), duration(hc.get('timeout'), 30.0),
            int(hc.get('retries') or 3), duration(hc.get('start_period'), 0.0),
            duration(hc.get('start_interval'), None))


def create_args(project, name, number=1, elf=None):
    """The `docker create` options of a service, and its command."""
    svc = project.services[name]
    for key in svc:
        if key in IGNORED:
            warn(f'service "{name}": {key} is ignored (no namespaces or cgroups here; '
                 'containers share the host network)')
    args = ['--name', project.container_name(name, number)]
    if svc.get('hostname'):
        args += ['-h', str(svc['hostname'])]
    for k, v in key_values(svc.get('environment')).items():
        args += ['-e', k if v is None else f'{k}={v}']
    for item in as_list(svc.get('env_file')):
        path, required = (item.get('path'), item.get('required', True)) if isinstance(item, dict) else (item, True)
        path = project.path(path)
        if not os.path.isfile(path):
            if required:
                raise ComposeError(f'env file {path} not found')
            continue
        args += ['--env-file', path]
    for vol in as_list(svc.get('volumes')):
        args += volume_args(project, name, vol)
    for t in as_list(svc.get('tmpfs')):
        args += ['--tmpfs', str(t).split(':')[0]]
    for port in as_list(svc.get('ports')):
        args += ['-p', port_spec(port)]
    if svc.get('working_dir'):
        args += ['-w', str(svc['working_dir'])]
    if svc.get('user') is not None:
        args += ['-u', str(svc['user'])]
    if svc.get('tty'):
        args.append('-t')
    if svc.get('stdin_open'):
        args.append('-i')
    if svc.get('read_only'):
        args.append('--read-only')
    restart = svc.get('restart')
    if restart is not None:
        args += ['--restart', 'no' if restart is False else str(restart)]
    if svc.get('stop_signal'):
        args += ['--stop-signal', str(svc['stop_signal'])]
    if svc.get('stop_grace_period') is not None:
        args += ['--stop-timeout', str(int(duration(svc['stop_grace_period'])))]
    for d in as_list(svc.get('dns')):
        args += ['--dns', str(d)]
    hosts = key_values(svc.get('extra_hosts'), sep=':') if isinstance(svc.get('extra_hosts'), list) \
        else key_values(svc.get('extra_hosts'))
    for host, ip in hosts.items():
        if ip is None and '=' in host:
            host, _, ip = host.partition('=')
        args += ['--add-host', f'{host}:{ip}']
    # Service discovery on the shared host network.
    for other in project.services:
        args += ['--add-host', f'{other}:127.0.0.1']
        cname = project.services[other].get('container_name')
        if cname and cname != other:
            args += ['--add-host', f'{cname}:127.0.0.1']
    labels = key_values(svc.get('labels'))
    for k, v in labels.items():
        args += ['-l', f'{k}={v or ""}']
    for item in as_list(svc.get('secrets')):
        args += file_ref(project, name, item, project.secrets, '/run/secrets/', 'secret')
    for item in as_list(svc.get('configs')):
        args += file_ref(project, name, item, project.configs, '/', 'config')
    ext = dict(svc.get('x-elf') or {})
    ext.update({k: v for k, v in (elf or {}).items() if v})
    if ext.get('isolate'):
        args.append('--isolate')
    if ext.get('cow'):
        args.append('--cow')
    if ext.get('owners'):
        args.append('--owners')
    return args


def port_spec(port):
    if isinstance(port, dict):
        target, published = port.get('target'), port.get('published', port.get('target'))
        proto = port.get('protocol')
        return f'{published}:{target}' + (f'/{proto}' if proto else '')
    text = str(port)
    body, slash, proto = text.partition('/')
    parts = body.split(':')
    if len(parts) == 1:
        return f'{parts[0]}:{parts[0]}' + (slash + proto if slash else '')
    return text


def volume_args(project, name, vol):
    if isinstance(vol, dict):
        kind = vol.get('type', 'volume')
        target = vol.get('target')
        ro = ':ro' if vol.get('read_only') else ''
        if kind == 'tmpfs':
            return ['--tmpfs', target]
        if kind == 'bind':
            src = project.path(vol['source'])
            if not os.path.exists(src) and (vol.get('bind') or {}).get('create_host_path', True):
                os.makedirs(src, exist_ok=True)
            return ['-v', f'{src}:{target}{ro}']
        if kind == 'volume':
            src = vol.get('source')
            return ['-v', f'{project.volume_name(src)}:{target}{ro}' if src else target]
        raise ComposeError(f'service "{name}": volume type {kind} is not supported')
    text = str(vol)
    parts = text.split(':')
    if len(parts) == 1:
        return ['-v', text]
    src, target = parts[0], parts[1]
    mode = parts[2] if len(parts) > 2 else ''
    mode = ':ro' if 'ro' in mode.split(',') else ''
    if src.startswith(('.', '/', '~')):
        src = project.path(src)
        if not os.path.exists(src):
            os.makedirs(src, exist_ok=True)   # compose creates a missing bind source
    else:
        if src not in project.volumes:
            raise ComposeError(f'service "{name}" refers to undefined volume {src}: invalid compose project')
        src = project.volume_name(src)
    return ['-v', f'{src}:{target}{mode}']


def file_ref(project, name, item, table, prefix, what):
    source, target = (item, None) if isinstance(item, str) else (item.get('source'), item.get('target'))
    spec = table.get(source)
    if spec is None:
        raise ComposeError(f'service "{name}" refers to undefined {what} {source}')
    if 'file' in spec:
        path = project.path(spec['file'])
    elif 'environment' in spec or 'content' in spec:
        data = spec.get('content')
        if data is None:
            data = project.env.get(spec['environment'], '')
        holder = Path(store_mod.Store().home, 'compose', project.name, what + 's')
        holder.mkdir(parents=True, exist_ok=True)
        path = str(holder / source)
        Path(path).write_text(data)
    else:
        raise ComposeError(f'{what} {source}: only file, environment and content sources are supported')
    target = target or source
    if not target.startswith('/'):
        target = prefix + target
    return ['-v', f'{path}:{target}:ro']


def config_hash(project, name, image_id):
    svc = dict(project.services[name])
    blob = json.dumps({'svc': svc, 'image': image_id}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


# ---------------------------------------------------------------- containers
class Compose:
    def __init__(self, st, project):
        self.st, self.p = st, project
        import docker_cli
        self.cli = docker_cli

    def containers(self, service=None, all_states=True):
        out = []
        for c in self.st.containers():
            labels = c['Config'].get('Labels') or {}
            if labels.get(LABEL + 'project') != self.p.name:
                continue
            if service and labels.get(LABEL + 'service') != service:
                continue
            if labels.get(LABEL + 'oneoff') == 'True' and service is None:
                continue
            c = runtime.refresh(self.st, c)
            if all_states or c['State']['Status'] in ('running', 'restarting'):
                out.append(c)
        return sorted(out, key=lambda c: c['Name'])

    def service_of(self, record):
        return (record['Config'].get('Labels') or {}).get(LABEL + 'service')

    def image_for(self, name, build=False, pull='missing'):
        svc = self.p.services[name]
        image = self.p.image_name(name)
        if 'build' in svc:
            have = None
            try:
                have = self.st.resolve_image(image)
            except store_mod.StoreError:
                pass
            if build or not have:
                self.build(name)
            return self.st.resolve_image(image), image
        return self.cli.ensure_image(self.st, image, pull, quiet=False), image

    def build(self, name, no_cache=False, pull=False):
        import build as build_mod
        spec = self.p.services[name]['build']
        spec = {'context': spec} if isinstance(spec, str) else dict(spec)
        context = self.p.path(spec.get('context', '.'))
        args = ['-t', self.p.image_name(name)]
        if spec.get('dockerfile'):
            df = spec['dockerfile']
            args += ['-f', df if df.startswith('/') else str(Path(context, df))]
        if spec.get('dockerfile_inline'):
            inline = Path(self.st.home, 'compose', self.p.name, f'{name}.Dockerfile')
            inline.parent.mkdir(parents=True, exist_ok=True)
            inline.write_text(spec['dockerfile_inline'])
            args += ['-f', str(inline)]
        for k, v in key_values(spec.get('args')).items():
            args += ['--build-arg', k if v is None else f'{k}={v}']
        if spec.get('target'):
            args += ['--target', spec['target']]
        for k, v in key_values(spec.get('labels')).items():
            args += ['--label', f'{k}={v or ""}']
        if no_cache or spec.get('no_cache'):
            args.append('--no-cache')
        for s in as_list(spec.get('secrets')):
            src = s if isinstance(s, str) else s.get('source')
            sp = self.p.secrets.get(src) or {}
            if 'file' in sp:
                args += ['--secret', f'id={src},src={self.p.path(sp["file"])}']
        print(f' Building {name}', file=sys.stderr)
        code = build_mod.cmd_build(self.st, args + [context])
        if code:
            raise ComposeError(f'failed to build service "{name}"')

    def create(self, name, number=1, build=False, pull='missing', elf=None, oneoff=None):
        image_id, image = self.image_for(name, build, pull)
        args = create_args(self.p, name, number, elf)
        if oneoff:
            args[1] = oneoff['name']
        labels = {LABEL + 'project': self.p.name, LABEL + 'service': name,
                  LABEL + 'container-number': str(number),
                  LABEL + 'config-hash': config_hash(self.p, name, image_id),
                  LABEL + 'project.working_dir': str(self.p.dir),
                  LABEL + 'project.config_files': ','.join(map(str, self.p.files)),
                  LABEL + 'oneoff': 'True' if oneoff else 'False'}
        for k, v in labels.items():
            args += ['-l', f'{k}={v}']
        for vol in as_list(self.p.services[name].get('volumes')):
            self.ensure_volume(vol)
        svc = self.p.services[name]
        if oneoff:
            args += oneoff.get('extra', [])
        cli = self.cli
        cli.check_unsupported(args)
        a = cli.run_parser('create').parse_args(args + [image])
        a.command = []
        record = cli.new_record(self.st, a, image_id, image)
        cfg = record['Config']
        if oneoff and oneoff.get('entrypoint') is not None:
            cfg['Entrypoint'], cfg['Cmd'] = oneoff['entrypoint'], None
        elif svc.get('entrypoint') is not None:
            cfg['Entrypoint'] = command_list(svc['entrypoint'])
            cfg['Cmd'] = None
        if oneoff and oneoff.get('command'):
            cfg['Cmd'] = oneoff['command']
        elif svc.get('command') is not None:
            cfg['Cmd'] = command_list(svc['command'])
        if oneoff and oneoff.get('rm'):
            record['HostConfig']['AutoRemove'] = True
        runtime.create(self.st, record)
        return self.st.load_container(record['Id'])

    def ensure_volume(self, vol):
        src = vol.get('source') if isinstance(vol, dict) and vol.get('type', 'volume') == 'volume' else \
            (str(vol).split(':')[0] if isinstance(vol, str) and ':' in str(vol) else None)
        if not src or src.startswith(('.', '/', '~')):
            return
        spec = self.p.volumes.get(src) or {}
        vname = self.p.volume_name(src)
        if spec.get('external'):
            if not (self.st.volume_dir(vname) / 'data').is_dir():
                raise ComposeError(f'external volume "{vname}" not found')
            return
        if not (self.st.volume_dir(vname) / 'data').is_dir():
            print(f' Volume "{vname}"  Created', file=sys.stderr)
            self.st.create_volume(vname, {LABEL + 'project': self.p.name, LABEL + 'volume': src})

    # ---- dependency conditions
    def healthy(self, record, name, deadline):
        image_cfg = self.st.image_info(record['Image'])['config'].get('config', {})
        hc = healthcheck(self.p, name, image_cfg)
        if hc is None:
            raise ComposeError(f'service "{name}" has no healthcheck: service_healthy cannot be met')
        argv, interval, timeout, retries, start_period, start_interval = hc
        began, failures = time.time(), 0
        while time.time() < deadline:
            record = runtime.refresh(self.st, self.st.load_container(record['Id']))
            if record['State']['Status'] not in ('running', 'restarting'):
                raise ComposeError(f'container {record["Name"]} exited ({record["State"].get("ExitCode")})')
            code = self.probe(record, argv, timeout)
            if code == 0:
                return
            in_start = time.time() - began < start_period
            if not in_start:
                failures += 1
                if failures >= retries:
                    raise ComposeError(f'container {record["Name"]} is unhealthy')
            time.sleep(min(start_interval or interval, interval) if in_start else interval)
        raise ComposeError(f'container {record["Name"]}: timed out waiting to be healthy')

    def probe(self, record, argv, timeout):
        cmd, _ = runtime.command_line(self.st, record, command=argv)
        try:
            p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, cwd=str(runtime.rootfs_of(self.st, record)),
                               timeout=timeout, start_new_session=True)
            return p.returncode
        except subprocess.TimeoutExpired:
            return 124

    def wait_for(self, name, timeout=600):
        deadline = time.time() + timeout
        for dep, cond in self.p.conditions(name).items():
            recs = self.containers(dep)
            if not recs:
                continue
            for r in recs:
                if cond == 'service_healthy':
                    print(f' Container {r["Name"]}  Waiting', file=sys.stderr)
                    self.healthy(r, dep, deadline)
                    print(f' Container {r["Name"]}  Healthy', file=sys.stderr)
                elif cond == 'service_completed_successfully':
                    code = runtime.wait(self.st, r)
                    if code != 0:
                        raise ComposeError(f'service "{dep}" didn\'t complete successfully: exit {code}')

    # ---- commands
    def up(self, names=(), detach=False, build=False, force=False, no_recreate=False, orphans=False,
           pull='missing', abort=False, exit_from=None, wait=False, elf=None, no_start=False,
           timeout=None, no_deps=False):
        services = self.p.active(names) if not no_deps else list(names)
        if orphans:
            for c in self.containers():
                if self.service_of(c) not in self.p.services:
                    runtime.remove(self.st, c, force=True)
                    print(f' Container {c["Name"]}  Removed', file=sys.stderr)
        started = []
        for name in services:
            recs = self.containers(name)
            image_id, _ = self.image_for(name, build, pull)
            want = config_hash(self.p, name, image_id)
            rec = recs[0] if recs else None
            if rec and not no_recreate and (force or
                                            (rec['Config'].get('Labels') or {}).get(LABEL + 'config-hash') != want):
                runtime.stop(self.st, rec, timeout)
                runtime.remove(self.st, self.st.load_container(rec['Id']), force=True)
                print(f' Container {rec["Name"]}  Recreate', file=sys.stderr)
                rec = None
            if rec is None:
                rec = self.create(name, build=False, pull='never' if 'build' not in self.p.services[name]
                                  else 'missing', elf=elf)
                print(f' Container {rec["Name"]}  Created', file=sys.stderr)
            if no_start:
                continue
            self.wait_for(name)
            rec = runtime.refresh(self.st, self.st.load_container(rec['Id']))
            if rec['State']['Status'] not in ('running', 'restarting'):
                runtime.start_detached(self.st, rec)
                print(f' Container {rec["Name"]}  Started', file=sys.stderr)
            else:
                print(f' Container {rec["Name"]}  Running', file=sys.stderr)
            started.append(rec['Id'])
        if wait:
            for name in services:
                for r in self.containers(name):
                    image_cfg = self.st.image_info(r['Image'])['config'].get('config', {})
                    if healthcheck(self.p, name, image_cfg):
                        self.healthy(r, name, time.time() + 600)
        if detach or no_start:
            return 0
        return self.attach(started, abort or exit_from is not None, exit_from, timeout)

    def attach(self, ids, abort, exit_from, timeout):
        """Foreground up: every container's output, prefixed, until all exit
        (or one does, with --abort-on-container-exit); Ctrl-C stops them."""
        records = {i: self.st.load_container(i) for i in ids}
        width = max((len(r['Name']) for r in records.values()), default=0)
        files = {}
        for i, r in records.items():
            path = self.st.container_dir(i) / 'log'
            f = open(path, 'rb') if path.exists() else None
            files[i] = [f, b'']
        stopping = {'flag': False}

        def interrupt(signum, frame):
            if stopping['flag']:
                raise KeyboardInterrupt
            stopping['flag'] = True
            print('Gracefully stopping... (press Ctrl+C again to force)', file=sys.stderr)
        old = signal.signal(signal.SIGINT, interrupt)
        exit_code = 0
        try:
            done = set()
            while True:
                active = False
                for i, r in records.items():
                    f = files[i][0]
                    if f is None:
                        path = self.st.container_dir(i) / 'log'
                        if path.exists():
                            files[i][0] = f = open(path, 'rb')
                    if f is not None:
                        chunk = f.read(65536)
                        if chunk:
                            active = True
                            data = files[i][1] + chunk
                            *lines, files[i][1] = data.split(b'\n')
                            for line in lines:
                                sys.stdout.write(f'{r["Name"]:<{width}}  | ' +
                                                 line.decode(errors='replace') + '\n')
                            sys.stdout.flush()
                    if i not in done:
                        cur = runtime.refresh(self.st, self.st.load_container(i))
                        if cur['State']['Status'] not in ('running', 'restarting'):
                            done.add(i)
                            if f is not None:
                                rest = files[i][1] + f.read()
                                for line in rest.split(b'\n'):
                                    if line:
                                        sys.stdout.write(f'{r["Name"]:<{width}}  | ' +
                                                         line.decode(errors='replace') + '\n')
                                files[i][1] = b''
                            code = cur['State'].get('ExitCode') or 0
                            print(f'{r["Name"]} exited with code {code}')
                            sys.stdout.flush()
                            svc = self.service_of(cur)
                            if exit_from and svc == exit_from:
                                exit_code = code
                            if abort and (exit_from is None or svc == exit_from):
                                if exit_from is None:
                                    exit_code = code
                                stopping['flag'] = True
                if stopping['flag'] or len(done) == len(records):
                    break
                if not active:
                    time.sleep(0.2)
        finally:
            signal.signal(signal.SIGINT, old)
        if stopping['flag']:
            for i in records:
                rec = runtime.refresh(self.st, self.st.load_container(i))
                if rec['State']['Status'] in ('running', 'restarting'):
                    runtime.stop(self.st, rec, timeout)
                    print(f' Container {rec["Name"]}  Stopped', file=sys.stderr)
        return exit_code

    def down(self, volumes=False, rmi=None, orphans=False, timeout=None):
        recs = self.containers()
        for c in reversed(self.order_records(recs)):
            if self.service_of(c) not in self.p.services and not orphans:
                continue
            if c['State']['Status'] in ('running', 'restarting'):
                runtime.stop(self.st, c, timeout)
                print(f' Container {c["Name"]}  Stopped', file=sys.stderr)
            runtime.remove(self.st, self.st.load_container(c['Id']), force=True)
            print(f' Container {c["Name"]}  Removed', file=sys.stderr)
        for c in self.st.containers():
            labels = c['Config'].get('Labels') or {}
            if labels.get(LABEL + 'project') == self.p.name and labels.get(LABEL + 'oneoff') == 'True':
                runtime.remove(self.st, c, force=True)
        if volumes:
            for vname, spec in self.p.volumes.items():
                if (spec or {}).get('external'):
                    continue
                d = self.st.volume_dir(self.p.volume_name(vname))
                if d.exists():
                    store_mod.remove(d)
                    print(f' Volume {self.p.volume_name(vname)}  Removed', file=sys.stderr)
        if rmi:
            for name, svc in self.p.services.items():
                if rmi == 'local' and 'image' in svc:
                    continue
                try:
                    image = self.p.image_name(name)
                    self.cli.cmd_rmi(self.st, ['-f', image])
                except (store_mod.StoreError, self.cli.Fail):
                    pass
        return 0

    def order_records(self, recs):
        order = self.p.order(list(self.p.services))
        return sorted(recs, key=lambda c: order.index(self.service_of(c)) if self.service_of(c) in order
                      else len(order))

    def resolve(self, service, index=1):
        recs = [r for r in self.containers(service)
                if (r['Config'].get('Labels') or {}).get(LABEL + 'container-number') == str(index)]
        if not recs:
            raise ComposeError(f'service "{service}" is not running')
        return recs[0]


# ---------------------------------------------------------------- command line
def main(st, argv):
    import argparse
    import docker_cli as cli

    top = cli.parser('compose', 'Define and run multi-container applications', add_help=False)
    top.add_argument('-f', '--file', action='append', default=[])
    top.add_argument('-p', '--project-name')
    top.add_argument('--project-directory')
    top.add_argument('--env-file', action='append', default=[])
    top.add_argument('--profile', action='append', default=[])
    top.add_argument('--ansi')
    top.add_argument('--progress')
    top.add_argument('--parallel')
    top.add_argument('--compatibility', action='store_true')
    top.add_argument('--dry-run', action='store_true')
    top.add_argument('command', nargs='?')
    top.add_argument('rest', nargs=argparse.REMAINDER)
    if argv and argv[0] in ('-h', '--help'):
        print(__doc__.strip())
        return 0
    a = top.parse_args(argv)
    if a.command in (None, 'help'):
        print(__doc__.strip())
        return 0
    if a.command == 'version':
        print('Docker Compose version v2.40.0-elf')
        return 0
    if a.command == 'ls':
        return cmd_ls(st, a.rest)
    handler = COMMANDS.get(a.command)
    if handler is None:
        raise cli.Fail(f"docker: '{a.command}' is not a docker compose command.")
    try:
        project = Project(a.file, a.project_directory, a.project_name, a.env_file, a.profile)
        return handler(Compose(st, project), a.rest) or 0
    except (ComposeError, yamlite.YAMLError) as e:
        raise cli.Fail(str(e), 1)


def sub(prog):
    import docker_cli as cli
    return cli.parser(f'compose {prog}')


def elf_flags(p):
    p.add_argument('--isolate', action='store_true', help='every container under the broker (ELF)')
    p.add_argument('--cow', action='store_true', help='copy-on-write containers (ELF)')
    p.add_argument('--owners', action='store_true', help='owner database (ELF)')


def cmd_up(c, args):
    p = sub('up')
    p.add_argument('-d', '--detach', action='store_true')
    p.add_argument('--build', action='store_true')
    p.add_argument('--no-build', action='store_true')
    p.add_argument('--force-recreate', action='store_true')
    p.add_argument('--no-recreate', action='store_true')
    p.add_argument('--no-deps', action='store_true')
    p.add_argument('--no-start', action='store_true')
    p.add_argument('--remove-orphans', action='store_true')
    p.add_argument('--abort-on-container-exit', action='store_true')
    p.add_argument('--exit-code-from')
    p.add_argument('--wait', action='store_true')
    p.add_argument('--wait-timeout', type=int)
    p.add_argument('--pull', default='missing', choices=['always', 'missing', 'never', 'build'])
    p.add_argument('-t', '--timeout', type=int)
    p.add_argument('--quiet-pull', action='store_true')
    p.add_argument('--no-color', action='store_true')
    p.add_argument('--no-log-prefix', action='store_true')
    p.add_argument('-y', '--yes', action='store_true')
    elf_flags(p)
    p.add_argument('services', nargs='*')
    a = p.parse_args(args)
    return c.up(a.services, a.detach or a.wait, a.build, a.force_recreate, a.no_recreate, a.remove_orphans,
                a.pull if a.pull != 'build' else 'missing', a.abort_on_container_exit, a.exit_code_from,
                a.wait, dict(isolate=a.isolate, cow=a.cow, owners=a.owners), a.no_start, a.timeout, a.no_deps)


def cmd_create(c, args):
    p = sub('create')
    p.add_argument('--build', action='store_true')
    p.add_argument('--force-recreate', action='store_true')
    p.add_argument('--pull', default='missing')
    elf_flags(p)
    p.add_argument('services', nargs='*')
    a = p.parse_args(args)
    return c.up(a.services, build=a.build, force=a.force_recreate, pull=a.pull, no_start=True,
                elf=dict(isolate=a.isolate, cow=a.cow, owners=a.owners))


def cmd_down(c, args):
    p = sub('down')
    p.add_argument('-v', '--volumes', action='store_true')
    p.add_argument('--rmi', choices=['all', 'local'])
    p.add_argument('--remove-orphans', action='store_true')
    p.add_argument('-t', '--timeout', type=int)
    a = p.parse_args(args)
    return c.down(a.volumes, a.rmi, a.remove_orphans, a.timeout)


def cmd_ps(c, args):
    import fmt
    p = sub('ps')
    p.add_argument('-a', '--all', action='store_true')
    p.add_argument('-q', '--quiet', action='store_true')
    p.add_argument('--services', action='store_true')
    p.add_argument('--format')
    p.add_argument('--status', action='append', default=[])
    p.add_argument('services_', nargs='*', metavar='services')
    a = p.parse_args(args)
    recs = [r for r in c.containers(all_states=a.all or bool(a.status))
            if (not a.services_ or c.service_of(r) in a.services_) and
            (not a.status or r['State']['Status'] in a.status)]
    if a.services:
        for s in dict.fromkeys(c.service_of(r) for r in recs):
            print(s)
        return 0
    if a.quiet:
        for r in recs:
            print(r['Id'])
        return 0
    rows = []
    for r in recs:
        row = c.cli.container_row(c.st, r)
        row['Service'] = c.service_of(r)
        row['Name'] = r['Name']
        row['Project'] = c.p.name
        row['Publishers'] = row['Ports']
        rows.append(row)
    if a.format == 'json':
        for row in rows:
            print(json.dumps(row))
        return 0
    if a.format:
        for row in rows:
            print(fmt.render(a.format, row))
        return 0
    print(fmt.table([[r['Name'], r['Image'], r['Command'], r['Service'], r['RunningFor'], r['Status'], r['Ports']]
                     for r in rows], ['NAME', 'IMAGE', 'COMMAND', 'SERVICE', 'CREATED', 'STATUS', 'PORTS']))
    return 0


def cmd_logs(c, args):
    p = sub('logs')
    p.add_argument('-f', '--follow', action='store_true')
    p.add_argument('-n', '--tail')
    p.add_argument('-t', '--timestamps', action='store_true')
    p.add_argument('--no-color', action='store_true')
    p.add_argument('--no-log-prefix', action='store_true')
    p.add_argument('services', nargs='*')
    a = p.parse_args(args)
    recs = [r for r in c.containers() if not a.services or c.service_of(r) in a.services]
    width = max((len(r['Name']) for r in recs), default=0)
    tail = None if a.tail in (None, 'all') else int(a.tail)
    for r in recs:
        path = c.st.container_dir(r['Id']) / 'log'
        if not path.exists():
            continue
        lines = path.read_bytes().decode(errors='replace').splitlines()
        if tail is not None:
            lines = lines[-tail:] if tail else []
        for line in lines:
            print(line if a.no_log_prefix else f'{r["Name"]:<{width}}  | {line}')
    sys.stdout.flush()
    if a.follow:
        return follow(c, recs, width, a.no_log_prefix)
    return 0


def follow(c, recs, width, no_prefix):
    files = {}
    for r in recs:
        path = c.st.container_dir(r['Id']) / 'log'
        f = open(path, 'rb') if path.exists() else None
        if f:
            f.seek(0, 2)
        files[r['Id']] = [f, b'', r]
    try:
        while True:
            active = False
            alive = False
            for cid, entry in files.items():
                f, buf, r = entry
                if f is None:
                    continue
                chunk = f.read(65536)
                if chunk:
                    active = True
                    *lines, entry[1] = (buf + chunk).split(b'\n')
                    for line in lines:
                        text = line.decode(errors='replace')
                        print(text if no_prefix else f'{r["Name"]:<{width}}  | {text}')
                    sys.stdout.flush()
                cur = runtime.refresh(c.st, c.st.load_container(cid))
                alive = alive or cur['State']['Status'] in ('running', 'restarting')
            if not alive and not active:
                return 0
            if not active:
                time.sleep(0.2)
    except KeyboardInterrupt:
        return 0


def cmd_exec(c, args):
    import docker_cli as cli
    p = sub('exec')
    p.add_argument('-d', '--detach', action='store_true')
    p.add_argument('-T', '--no-TTY', action='store_true')
    p.add_argument('-i', '--interactive', action='store_true', default=True)
    p.add_argument('-e', '--env', action='append', default=[])
    p.add_argument('-u', '--user')
    p.add_argument('-w', '--workdir')
    p.add_argument('--index', type=int, default=1)
    p.add_argument('--privileged', action='store_true')
    p.add_argument('service')
    options, service, command = cli.split_options(args, {'-e', '--env', '-u', '--user', '-w', '--workdir',
                                                        '--index'})
    a = p.parse_args(options + ([service] if service else []))
    if not command:
        raise ComposeError('exec requires a service and a command')
    rec = c.resolve(a.service, a.index)
    tty = not a.no_TTY and os.isatty(0) and os.isatty(1)
    return runtime.exec_in(c.st, rec, command, tty or (os.isatty(0) and not a.no_TTY), tty, a.detach,
                           cli.env_entries(a.env), a.workdir, a.user)


def cmd_run(c, args):
    import docker_cli as cli
    p = sub('run')
    p.add_argument('-d', '--detach', action='store_true')
    p.add_argument('--rm', action='store_true')
    p.add_argument('-T', '--no-TTY', action='store_true')
    p.add_argument('-i', '--interactive', action='store_true', default=True)
    p.add_argument('-e', '--env', action='append', default=[])
    p.add_argument('-u', '--user')
    p.add_argument('-w', '--workdir')
    p.add_argument('-v', '--volume', action='append', default=[])
    p.add_argument('-p', '--publish', action='append', default=[])
    p.add_argument('-l', '--label', action='append', default=[])
    p.add_argument('--name')
    p.add_argument('--entrypoint')
    p.add_argument('--no-deps', action='store_true')
    p.add_argument('--build', action='store_true')
    p.add_argument('--service-ports', action='store_true')
    p.add_argument('--quiet-pull', action='store_true')
    elf_flags(p)
    p.add_argument('service')
    options, service, command = cli.split_options(
        args, {'-e', '--env', '-u', '--user', '-w', '--workdir', '-v', '--volume', '-p', '--publish',
               '-l', '--label', '--name', '--entrypoint'})
    a = p.parse_args(options + ([service] if service else []))
    if a.service not in c.p.services:
        raise ComposeError(f'no such service: {a.service}')
    elf = dict(isolate=a.isolate, cow=a.cow, owners=a.owners)
    if not a.no_deps:
        deps = [d for d in c.p.active([a.service]) if d != a.service]
        if deps:
            c.up(deps, detach=True, elf=elf)
        c.wait_for(a.service)
    extra = []
    for e in a.env:
        extra += ['-e', e]
    for v in a.volume:
        extra += ['-v', v]
    for port in a.publish:
        extra += ['-p', port]
    for label in a.label:
        extra += ['-l', label]
    if a.user:
        extra += ['-u', a.user]
    if a.workdir:
        extra += ['-w', a.workdir]
    if not a.service_ports:
        svc = dict(c.p.services[a.service])
        svc.pop('ports', None)
        c.p.services[a.service] = svc
    number = 1 + sum(1 for r in c.st.containers()
                     if (r['Config'].get('Labels') or {}).get(LABEL + 'project') == c.p.name)
    name = a.name or f'{c.p.name}-{a.service}-run-{hashlib.sha256(os.urandom(8)).hexdigest()[:12]}'
    oneoff = {'name': name, 'extra': extra, 'rm': a.rm,
              'command': command or None,
              'entrypoint': (shlex.split(a.entrypoint) if a.entrypoint else []) if a.entrypoint is not None
              else None}
    rec = c.create(a.service, number=number, build=a.build, elf=elf, oneoff=oneoff)
    if a.detach:
        runtime.start_detached(c.st, rec)
        print(rec['Name'])
        return 0
    tty = not a.no_TTY and os.isatty(0) and os.isatty(1)
    return runtime.start_foreground(c.st, rec, a.interactive and os.isatty(0) and not a.no_TTY, tty)


def simple(action):
    def handler(c, args):
        p = sub(action)
        if action in ('stop', 'restart'):
            p.add_argument('-t', '--timeout', type=int)
        if action == 'kill':
            p.add_argument('-s', '--signal', default='SIGKILL')
        if action == 'rm':
            p.add_argument('-f', '--force', action='store_true')
            p.add_argument('-s', '--stop', action='store_true')
            p.add_argument('-v', '--volumes', action='store_true')
        p.add_argument('services', nargs='*')
        a = p.parse_args(args)
        names = a.services or list(c.p.services)
        recs = [r for r in c.order_records(c.containers()) if c.service_of(r) in names]
        if action in ('stop', 'kill') or (action == 'rm' and a.stop):
            recs = list(reversed(recs))
        for r in recs:
            r = runtime.refresh(c.st, c.st.load_container(r['Id']))
            running = r['State']['Status'] in ('running', 'restarting')
            if action == 'start':
                if not running:
                    c.wait_for(c.service_of(r))
                    runtime.start_detached(c.st, r)
                    print(f' Container {r["Name"]}  Started', file=sys.stderr)
            elif action == 'stop' and running:
                runtime.stop(c.st, r, a.timeout)
                print(f' Container {r["Name"]}  Stopped', file=sys.stderr)
            elif action == 'restart':
                if running:
                    runtime.stop(c.st, r, a.timeout)
                runtime.start_detached(c.st, c.st.load_container(r['Id']))
                print(f' Container {r["Name"]}  Started', file=sys.stderr)
            elif action == 'kill' and running:
                runtime.kill(c.st, r, runtime.parse_signal(a.signal))
                print(f' Container {r["Name"]}  Killed', file=sys.stderr)
            elif action == 'rm':
                if running and not a.stop:
                    continue
                if running:
                    runtime.stop(c.st, r)
                runtime.remove(c.st, c.st.load_container(r['Id']), force=True)
                print(f' Container {r["Name"]}  Removed', file=sys.stderr)
        return 0
    return handler


def cmd_build(c, args):
    p = sub('build')
    p.add_argument('--no-cache', action='store_true')
    p.add_argument('--pull', action='store_true')
    p.add_argument('-q', '--quiet', action='store_true')
    p.add_argument('--build-arg', action='append', default=[])
    p.add_argument('services', nargs='*')
    a = p.parse_args(args)
    for name in a.services or list(c.p.services):
        if 'build' in c.p.services[name]:
            if a.build_arg:
                spec = c.p.services[name]['build']
                spec = {'context': spec} if isinstance(spec, str) else dict(spec)
                merged = key_values(spec.get('args'))
                merged.update(key_values(a.build_arg))
                spec['args'] = merged
                c.p.services[name] = dict(c.p.services[name], build=spec)
            c.build(name, a.no_cache)
    return 0


def cmd_pull(c, args):
    p = sub('pull')
    p.add_argument('-q', '--quiet', action='store_true')
    p.add_argument('--ignore-pull-failures', action='store_true')
    p.add_argument('--ignore-buildable', action='store_true')
    p.add_argument('services', nargs='*')
    a = p.parse_args(args)
    for name in a.services or c.p.active():
        svc = c.p.services[name]
        if 'image' not in svc or ('build' in svc and a.ignore_buildable):
            continue
        try:
            c.cli.ensure_image(c.st, svc['image'], 'always', quiet=a.quiet)
        except Exception:
            if not a.ignore_pull_failures:
                raise
    return 0


def cmd_config(c, args):
    p = sub('config')
    p.add_argument('--services', action='store_true')
    p.add_argument('--volumes', action='store_true')
    p.add_argument('--images', action='store_true')
    p.add_argument('-q', '--quiet', action='store_true')
    p.add_argument('--format', default='yaml', choices=['yaml', 'json'])
    p.add_argument('--no-interpolate', action='store_true')
    a = p.parse_args(args)
    if a.quiet:
        return 0
    if a.services:
        print('\n'.join(c.p.active()))
        return 0
    if a.volumes:
        print('\n'.join(map(str, c.p.volumes)))
        return 0
    if a.images:
        print('\n'.join(c.p.image_name(n) for n in c.p.services))
        return 0
    out = dict(c.p.data)
    out['name'] = c.p.name
    out['services'] = c.p.services
    out = {'name': out.pop('name'), **out}
    print(json.dumps(out, indent=2) if a.format == 'json' else yamlite.dump(out), end='' if a.format == 'yaml'
          else '\n')
    return 0


def cmd_images(c, args):
    import fmt
    import images
    rows = []
    for r in c.containers():
        info = c.st.image_info(r['Image'])['info']
        rows.append([r['Name'], r['ImageName'], r['Image'][:12], images.human_size(info.get('size', 0))])
    print(fmt.table(rows, ['CONTAINER', 'IMAGE', 'IMAGE ID', 'SIZE']))
    return 0


def cmd_port(c, args):
    p = sub('port')
    p.add_argument('service')
    p.add_argument('private_port')
    a = p.parse_args(args)
    port = a.private_port.split('/')[0]
    for spec in as_list(c.p.services[a.service].get('ports')):
        pub, target = port_spec(spec).split('/')[0].split(':')[-2:]
        if target == port:
            print(f'0.0.0.0:{pub}')
            return 0
    return 1


def cmd_top(c, args):
    for r in c.containers(all_states=False):
        pid = r['State'].get('Pid')
        print(r['Name'])
        if pid:
            subprocess.run(['ps', '-o', 'pid,args', '-p', str(pid)])
    return 0


def cmd_ls(st, args):
    import docker_cli as cli
    import fmt
    p = cli.parser('compose ls')
    p.add_argument('-a', '--all', action='store_true')
    p.add_argument('-q', '--quiet', action='store_true')
    p.add_argument('--format')
    a = p.parse_args(args)
    projects = {}
    for r in st.containers():
        labels = r['Config'].get('Labels') or {}
        name = labels.get(LABEL + 'project')
        if not name:
            continue
        r = runtime.refresh(st, r)
        entry = projects.setdefault(name, {'running': 0, 'exited': 0, 'files': labels.get(LABEL + 'project.config_files', '')})
        entry['running' if r['State']['Status'] in ('running', 'restarting') else 'exited'] += 1
    rows = []
    for name, e in sorted(projects.items()):
        if not a.all and not e['running']:
            continue
        status = ', '.join(f'{k}({v})' for k, v in (('running', e['running']), ('exited', e['exited'])) if v)
        rows.append({'Name': name, 'Status': status, 'ConfigFiles': e['files']})
    if a.quiet:
        print('\n'.join(r['Name'] for r in rows))
    elif a.format == 'json':
        print(json.dumps(rows))
    else:
        print(fmt.table([[r['Name'], r['Status'], r['ConfigFiles']] for r in rows], ['NAME', 'STATUS', 'CONFIG FILES']))
    return 0


COMMANDS = {
    'up': cmd_up, 'create': cmd_create, 'down': cmd_down, 'ps': cmd_ps, 'logs': cmd_logs, 'exec': cmd_exec,
    'run': cmd_run, 'start': simple('start'), 'stop': simple('stop'), 'restart': simple('restart'),
    'kill': simple('kill'), 'rm': simple('rm'), 'build': cmd_build, 'pull': cmd_pull, 'config': cmd_config,
    'convert': cmd_config, 'images': cmd_images, 'port': cmd_port, 'top': cmd_top,
}
