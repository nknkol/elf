"""Container networks (docs/OCI.md, "网络与副本").

There are no network namespaces: every container (except --network host)
gets an address of its own on the loopback network, from 127.128.0.0/9,
and the payload moves its sockets there (src/payload/include/net_view.h):
binding the wildcard or 127.0.0.1 binds that address, 127.0.0.1 is the
container itself, ports below 1024 are 61000+p on the host. A network is
a set of containers: a container reaches the addresses of the containers
it shares a network with (its peers file, which the loader reads; the
broker enforces it with --isolate) and, on a user-defined network, finds
them by name and alias through its /etc/hosts, as Docker's DNS would.

  bridge   the default network: peers by address, no names (as Docker's)
  host     the host's network as it is (no address, ports as themselves)
  none     an address with no peers
  NAME     a user-defined network (docker network create, compose)
  container:ID   the address and peers of another container

-p HOST:CONTAINER publishes a port through a forwarder in the process
that runs the container (docker run, or its monitor), as docker-proxy:
connections to the host port go to the container's address."""
import json
import os
import socket
import threading
import time

import store as store_mod
from store import StoreError

POOL_FIRST = (127 << 24) | (128 << 16) | 2
POOL_LAST = (127 << 24) | (255 << 16) | (255 << 8) | 254
HOST_ALIAS = '127.127.0.1'       # the host's 127.0.0.1 (net_view.h NET_HOST_ALIAS)
PORT_BASE = 61000                # ports below 1024 of a container address
BUILTIN = ('bridge', 'host', 'none')


def dotted(ip):
    return '.'.join(str(ip >> s & 255) for s in (24, 16, 8, 0))


def number(text):
    parts = [int(p) for p in text.split('.')]
    return parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]


def in_pool(text):
    try:
        return POOL_FIRST - 2 <= number(text) <= POOL_LAST + 1
    except (ValueError, IndexError):
        return False


# ---------------------------------------------------------------- networks
def _file(st):
    return st.home / 'networks.json'


def _builtin(name):
    return {'Name': name, 'Id': name, 'Created': '0001-01-01T00:00:00Z', 'Driver': 'host' if name == 'host' else
            'null' if name == 'none' else 'bridge', 'Scope': 'local', 'Internal': False, 'Attachable': False,
            'Labels': {}, 'Options': {}}


def networks(st):
    """name -> spec, the built-in ones first."""
    out = {name: _builtin(name) for name in BUILTIN}
    out.update(store_mod.read_json(_file(st), {}))
    return out


def find(st, text):
    nets = networks(st)
    if text in nets:
        return nets[text]
    matches = [n for n in nets.values() if n['Id'].startswith(text)]
    if len(matches) == 1:
        return matches[0]
    raise StoreError(f'network {text} not found')


def create(st, name, driver='bridge', labels=None, internal=False, attachable=False, options=None,
           check=True):
    if driver not in ('bridge', None, ''):
        raise StoreError(f'network driver {driver} is not supported (only bridge)')
    if not name or not all(c.isalnum() or c in '_.-' for c in name):
        raise StoreError(f'invalid network name {name!r}')
    with st.lock():
        data = store_mod.read_json(_file(st), {})
        if name in data or name in BUILTIN:
            if check:
                raise StoreError(f'network with name {name} already exists')
            return networks(st)[name]
        spec = {'Name': name, 'Id': store_mod.Store.new_id(), 'Created': store_mod.now(), 'Driver': 'bridge',
                'Scope': 'local', 'Internal': bool(internal), 'Attachable': bool(attachable),
                'Labels': labels or {}, 'Options': options or {}}
        data[name] = spec
        store_mod.write_json(_file(st), data)
    return spec


def users(st, name):
    return [c for c in st.containers() if name in ((c.get('NetworkSettings') or {}).get('Networks') or {})]


def remove(st, text):
    spec = find(st, text)
    if spec['Name'] in BUILTIN:
        raise StoreError(f'{spec["Name"]} is a pre-defined network and cannot be removed')
    if users(st, spec['Name']):
        raise StoreError(f'error while removing network: network {spec["Name"]} id {spec["Id"]} has active endpoints')
    with st.lock():
        data = store_mod.read_json(_file(st), {})
        data.pop(spec['Name'], None)
        store_mod.write_json(_file(st), data)
    return spec


def inspect(st, text):
    spec = dict(find(st, text))
    spec['IPAM'] = {'Driver': 'default', 'Options': {},
                    'Config': [] if spec['Name'] in ('host', 'none') else [{'Subnet': '127.128.0.0/9'}]}
    spec['EnableIPv6'] = False
    spec['Containers'] = {}
    for c in users(st, spec['Name']):
        ip = address(st, c)
        spec['Containers'][c['Id']] = {'Name': c['Name'], 'IPv4Address': f'{ip}/9' if ip else '',
                                       'IPv6Address': '', 'MacAddress': '', 'EndpointID': c['Id'][:32]}
    return spec


# ---------------------------------------------------------------- containers
def mode(record):
    """The record's network mode ('host' for records made before networks)."""
    return record['HostConfig'].get('NetworkMode') or 'host'


def settings(record):
    return record.setdefault('NetworkSettings', {'IPAddress': '', 'Networks': {}})


def attach_new(st, record, mode_text, aliases=(), ip=None):
    """Sets a new record's network mode and first network (before create)."""
    if mode_text in ('default', None, ''):
        mode_text = 'bridge'
    if mode_text.startswith('container:') or mode_text.startswith('service:'):
        target = st.resolve_container(mode_text.split(':', 1)[1])
        record['HostConfig']['NetworkMode'] = 'container:' + target['Id']
        settings(record)
        return
    spec = find(st, mode_text)
    record['HostConfig']['NetworkMode'] = spec['Name']
    nets = {}
    if spec['Name'] not in ('host', 'none'):
        nets[spec['Name']] = {'Aliases': list(aliases), 'NetworkID': spec['Id']}
    elif aliases:
        raise StoreError('network-scoped aliases are only supported for user-defined networks')
    record['NetworkSettings'] = {'IPAddress': '', 'Networks': nets, 'RequestedIP': ip or ''}


def allocate(st, record, others):
    """Gives the record an address (under the store lock, at create)."""
    s = settings(record)
    m = mode(record)
    if m == 'host' or m.startswith('container:'):
        s['IPAddress'] = ''
        return
    used = {address(st, c) for c in others}
    want = s.pop('RequestedIP', '')
    if want:
        if not in_pool(want):
            raise StoreError(f'--ip {want}: the address must be in 127.128.0.0/9')
        if want in used:
            raise StoreError(f'Address already in use: {want}')
        ip = want
    else:
        ip = None
        for n in range(POOL_FIRST, POOL_LAST + 1):
            if n & 255 in (0, 255):
                continue
            if dotted(n) not in used:
                ip = dotted(n)
                break
        if not ip:
            raise StoreError('no free container address left in 127.128.0.0/9')
    s['IPAddress'] = ip
    for net in s['Networks'].values():
        net['IPAddress'] = ip


def address(st, record):
    """The address a container's sockets use ('' for the host network)."""
    m = mode(record)
    if m.startswith('container:'):
        try:
            return address(st, st.load_container(m.split(':', 1)[1]))
        except (OSError, ValueError):
            return ''
    return (record.get('NetworkSettings') or {}).get('IPAddress') or ''


def _networks_of(st, record, by_id):
    m = mode(record)
    if m.startswith('container:'):
        target = by_id.get(m.split(':', 1)[1])
        return _networks_of(st, target, by_id) if target else {}
    return (record.get('NetworkSettings') or {}).get('Networks') or {}


def refresh(st):
    """Rewrites every container's peers file and /etc/hosts from the
    networks they are on (after create, rm, connect, disconnect, rename)."""
    records = st.containers()
    by_id = {c['Id']: c for c in records}
    for c in records:
        cdir = st.container_dir(c['Id'])
        if not cdir.exists() or mode(c) == 'host':
            continue
        ip = address(st, c)
        mine = _networks_of(st, c, by_id)
        peers, names = set(), []
        for d in records:
            if d['Id'] == c['Id'] or mode(d) == 'host':
                continue
            dip = address(st, d)
            if not dip or dip == ip:
                continue
            theirs = _networks_of(st, d, by_id)
            for net in set(mine) & set(theirs):
                peers.add(dip)
                if net != 'bridge':   # user-defined networks resolve names
                    names.append((dip, [d['Name']] + list(theirs[net].get('Aliases') or [])))
        write_in_place(cdir / 'peers', ''.join(p + '\n' for p in sorted(peers, key=number)))
        hostname = c['Config']['Hostname']
        lines = ['127.0.0.1\tlocalhost', '::1\tlocalhost ip6-localhost ip6-loopback']
        if ip:
            lines.append(f'{ip}\t{hostname}' + (f' {c["Name"]}' if c['Name'] != hostname else ''))
        lines += [f'{i}\t{n}' for n, i in c['HostConfig'].get('ExtraHosts') or []]
        seen = set()
        for dip, aliases in names:
            fresh = [a for a in dict.fromkeys(aliases) if (dip, a) not in seen]
            seen.update((dip, a) for a in fresh)
            if fresh:
                lines.append(f'{dip}\t' + ' '.join(fresh))
        write_in_place(cdir / 'etc' / 'hosts', '\n'.join(lines) + '\n')


def write_in_place(path, text):
    """Rewritten in place: a running container has the file bound."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a+') as f:
        f.seek(0)
        if f.read() == text:
            return
        f.seek(0)
        f.truncate()
        f.write(text)


def connect(st, record, text, aliases=()):
    spec = find(st, text)
    if spec['Name'] in ('host', 'none') or mode(record) in ('host', 'none') or \
            mode(record).startswith('container:'):
        raise StoreError(f'container cannot be connected to network {spec["Name"]} in network mode '
                         f'{mode(record)}')
    with st.lock():
        record = st.load_container(record['Id'])
        nets = settings(record)['Networks']
        if spec['Name'] in nets:
            raise StoreError(f'endpoint with name {record["Name"]} already exists in network {spec["Name"]}')
        nets[spec['Name']] = {'Aliases': list(aliases), 'NetworkID': spec['Id'],
                              'IPAddress': address(st, record)}
        st.save_container(record)
    refresh(st)


def disconnect(st, record, text):
    spec = find(st, text)
    with st.lock():
        record = st.load_container(record['Id'])
        nets = settings(record)['Networks']
        if spec['Name'] not in nets:
            raise StoreError(f'container {record["Name"]} is not connected to network {spec["Name"]}')
        del nets[spec['Name']]
        st.save_container(record)
    refresh(st)


def loader_options(st, record, cdir):
    ip = address(st, record)
    if not ip:
        return []
    return ['--net-addr', ip, '--net-peers', str(cdir / 'peers')]


# ---------------------------------------------------------------- ports
def parse_publish(spec):
    """'[ip:][host[-host]:]container[-container][/proto]' -> [(ip, host, container, proto)];
    host 0: any free port."""
    body, _, proto = spec.partition('/')
    proto = proto or 'tcp'
    if proto != 'tcp':
        raise StoreError(f'-p {spec}: only TCP ports can be published here')
    parts = body.rsplit(':', 2)
    ip, host, cont = ('0.0.0.0', '', parts[0]) if len(parts) == 1 else \
        ('0.0.0.0', parts[0], parts[1]) if len(parts) == 2 else (parts[0] or '0.0.0.0', parts[1], parts[2])
    ip = ip.strip('[]')

    def span(text):
        a, _, b = text.partition('-')
        a, b = int(a), int(b or a)
        if not (0 < a <= b < 65536):
            raise StoreError(f'invalid port {text} in -p {spec}')
        return list(range(a, b + 1))
    conts = span(cont)
    if any(reserved_port(c) for c in conts):
        raise StoreError(f'-p {spec}: container ports {PORT_BASE + 1}-{PORT_BASE + 1023} stand for '
                         'ports below 1024 here')
    hosts = span(host) if host else [0] * len(conts)
    if len(hosts) == 1 and len(conts) > 1:
        hosts = [hosts[0] + i for i in range(len(conts))] if host and '-' not in host else hosts * len(conts)
    if len(hosts) != len(conts):
        raise StoreError(f'-p {spec}: the host and container port ranges differ in size')
    return [(ip, h, c, proto) for h, c in zip(hosts, conts)]


def container_port(port):
    return PORT_BASE + port if 0 < port < 1024 else port


def reserved_port(port):
    """A host port standing for a port below 1024 (the guest cannot use it)."""
    return PORT_BASE < port < PORT_BASE + 1024


class Publisher:
    """The forwarders of a running container's published ports."""

    def __init__(self, target, specs):
        self.target = target
        self.specs = specs
        self.listeners = []
        self.ports = {}
        self.closed = False

    def start(self):
        try:
            for spec in self.specs:
                for ip, host, cont, proto in parse_publish(spec):
                    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
                    s = socket.socket(family)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    try:
                        s.bind((ip, host))
                    except OSError as e:
                        s.close()
                        raise StoreError(f'driver failed programming external connectivity: '
                                         f'Bind for {ip}:{host} failed: {e.strerror}') from None
                    s.listen(64)
                    self.listeners.append(s)
                    bound = s.getsockname()[1]
                    self.ports.setdefault(f'{cont}/{proto}', []).append({'HostIp': ip, 'HostPort': str(bound)})
                    threading.Thread(target=self.accept, args=(s, cont), daemon=True).start()
        except BaseException:
            self.stop()
            raise
        return self.ports

    def accept(self, s, cont):
        while not self.closed:
            try:
                client, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=self.forward, args=(client, cont), daemon=True).start()

    def forward(self, client, cont):
        try:
            upstream = socket.create_connection((self.target, container_port(cont)), timeout=10)
            upstream.settimeout(None)
        except OSError:
            client.close()
            return

        def pump(a, b):
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        t = threading.Thread(target=pump, args=(upstream, client), daemon=True)
        t.start()
        pump(client, upstream)
        t.join()
        client.close()
        upstream.close()

    def stop(self):
        self.closed = True
        for s in self.listeners:
            try:
                s.close()
            except OSError:
                pass
        self.listeners = []


def wait_listening(ip, port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((ip, container_port(port)), timeout=1):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def describe_ports(record):
    """'0.0.0.0:8080->80/tcp, ...' of a running container (docker ps)."""
    ports = (record.get('NetworkSettings') or {}).get('Ports') or {}
    out = []
    for key, bindings in ports.items():
        for b in bindings or []:
            out.append(f'{b["HostIp"]}:{b["HostPort"]}->{key}')
    if not out and mode(record) == 'host':
        return ', '.join(record['HostConfig'].get('PortBindings') or [])
    return ', '.join(out)


def dump(obj):
    return json.dumps(obj, indent=4)
