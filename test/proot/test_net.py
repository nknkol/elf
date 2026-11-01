#!/usr/bin/env python3
"""Container networks (net_view.h): with --net-addr each container has an
address of its own on the loopback network (127.128.0.0/9), so containers
can listen on the same port, and --net-peers lists the containers it may
reach.

Expected: a server binding 0.0.0.0:80 (or [::]:80, dual-stack) in one
container and another binding port 80 in a second one both run (port 80
is host port 61080 of each address); getsockname shows the address and
port 80; a peer connects to it and is seen as coming from its own
address; a container not listed as a peer is refused (ECONNREFUSED);
binding another container's address is EADDRNOTAVAIL; 127.0.0.1 is the
container itself; 127.127.0.1 is the host's 127.0.0.1; the host reaches a
container's port 80 at 61080, while the guest itself cannot bind or
connect to 61080 of a pool address (EACCES, ECONNREFUSED: the host ports
of ports below 1024 are reserved, so the mapping has no collisions). Both builds, plain and with --isolate (the
broker refuses the non-peer connect and the foreign bind)."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

SERVER = r'''
import socket, sys
family = socket.AF_INET6 if sys.argv[2] == '6' else socket.AF_INET
s = socket.socket(family)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 80))
s.listen()
print('BOUND ' + str(s.getsockname()[:2]), flush=True)
while True:
    c, peer = s.accept()
    c.sendall(f'{sys.argv[1]} {peer[0]} {peer[1] > 0}\n'.encode())
    c.close()
'''

CLIENT = r'''
import errno, json, socket, sys
a, c, host_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
out = {}
def ask(addr, port, family=socket.AF_INET):
    s = socket.socket(family)
    try:
        s.settimeout(5)
        s.connect((addr, port))
        name = s.getsockname()[:2]
        data = s.makefile().readline().strip()
        return [data, list(name)]
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e))
    finally:
        s.close()
out['peer'] = ask(a, 80)
out['peer_v6'] = ask('::ffff:' + a, 80, socket.AF_INET6)
out['not_peer'] = ask(c, 80)
s = socket.socket()
try:
    s.bind((a, 9000)); out['foreign_bind'] = 'bound'
except OSError as e:
    out['foreign_bind'] = errno.errorcode[e.errno]
s.close()
# localhost is this container: a server of its own on 127.0.0.1.
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 81)); srv.listen()
out['own_name'] = list(srv.getsockname()[:2])
cl = socket.create_connection(('127.0.0.1', 81), timeout=5)
conn, peer = srv.accept()
out['self_peer'] = peer[0]
conn.close(); cl.close(); srv.close()
out['host'] = ask('127.127.0.1', host_port)
# 61001-62023 stand for ports below 1024: not usable directly.
s = socket.socket()
try:
    s.bind(('0.0.0.0', 61080)); out['reserved_bind'] = 'bound'
except OSError as e:
    out['reserved_bind'] = errno.errorcode[e.errno]
s.close()
out['reserved_connect'] = ask(a, 61080)
print('RESULT ' + json.dumps(out))
'''

python = str(Path(sys.executable).resolve()).lstrip('/')


def host_server():
    """A server of the host on 127.0.0.1 (what 127.127.0.1 reaches)."""
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    s.listen()

    def serve():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            c.sendall(b'host\n')
            c.close()
    threading.Thread(target=serve, daemon=True).start()
    return s


with tempfile.TemporaryDirectory(prefix='net-', dir=lib.mode_capable()) as tmp:
    hs = host_server()
    host_port = hs.getsockname()[1]
    run = 0
    for suffix, loader in lib.loaders():
        for isolate in ([], ['--isolate']):
            run += 1
            what = (loader.name, isolate)
            a, b, c = (f'127.128.{run}.{n}' for n in (2, 3, 4))
            peers = {}
            for name, listed in (('a', [b]), ('b', [a]), ('c', [])):
                peers[name] = Path(tmp, f'peers-{run}-{name}')
                peers[name].write_text(''.join(x + '\n' for x in listed))

            def loader_argv(addr, name, *argv):
                return [str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container', '--root', '/',
                        '--net-addr', addr, '--net-peers', str(peers[name]), '--', python, '-B', *argv]
            servers = [subprocess.Popen(loader_argv(a, 'a', '-c', SERVER, 'from-a', '4'), cwd='/',
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True),
                       subprocess.Popen(loader_argv(c, 'c', '-c', SERVER, 'from-c', '6'), cwd='/',
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)]
            try:
                bound = [srv.stdout.readline().strip() for srv in servers]
                assert bound[0] == f"BOUND ('{a}', 80)" and bound[1] == f"BOUND ('::ffff:{c}', 80)", \
                    (what, bound, [srv.poll() for srv in servers])
                p = subprocess.run(loader_argv(b, 'b', '-c', CLIENT, a, c, str(host_port)), cwd='/',
                                   capture_output=True, text=True, timeout=60)
                lines = [line for line in p.stdout.splitlines() if line.startswith('RESULT ')]
                assert p.returncode == 0 and lines, (what, p.returncode, p.stdout[-2000:], p.stderr[-2000:])
                out = json.loads(lines[-1][7:])
                assert out['peer'][0] == f'from-a {b} True' and out['peer'][1][0] == b, (what, out['peer'])
                assert out['peer_v6'][0] == f'from-a {b} True', (what, out['peer_v6'])
                assert out['not_peer'] == 'ECONNREFUSED', (what, out['not_peer'])
                assert out['foreign_bind'] == 'EADDRNOTAVAIL', (what, out['foreign_bind'])
                assert out['own_name'] == [b, 81] and out['self_peer'] == b, (what, out)
                assert out['host'][0] == 'host', (what, out['host'])
                assert out['reserved_bind'] == 'EACCES' and out['reserved_connect'] == 'ECONNREFUSED', (what, out)
                # The host reaches the container's port 80 at 61080 of its address.
                with socket.create_connection((a, 61080), timeout=5) as s:
                    reply = s.makefile().readline().strip()
                assert reply == 'from-a 127.0.0.1 True', (what, reply)
                with socket.create_connection((c, 61080), timeout=5) as s:
                    assert s.makefile().readline().startswith('from-c'), what
            finally:
                for srv in servers:
                    srv.kill()
                    srv.wait()
            print('PASS: container networks (own address, port 80 twice, peers, refusal, localhost, host alias, reserved ports):',
                  loader.name, *isolate)
    hs.close()
