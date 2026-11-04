#!/usr/bin/env python3
"""Real images (docs/OCI.md, R1 "真实镜像"): each workload runs with
`docker run` plain and with --isolate, and once directly with elfloader on a
container's rootfs (the same argv, without the docker command). Expected:
every run prints the expected marker; docker's own cost is the rootfs copy
and start-up, not slower guest execution.

Images are pulled when missing (slow networks: `docker save` elsewhere and
`docker load` here first). ELF_OCI_HOME selects the store (default store)."""
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DOCKER = REPO / 'tools/oci/docker'
sys.path.insert(0, str(REPO / 'tools/oci'))

WORKLOADS = [
    ('busybox', [], 'busybox | head -1', 'BusyBox v'),
    # Offline: guest execution only (the others mostly measure the network).
    ('python:3.13-slim', [], 'python -c "import hashlib, os, tempfile\n'
     'for i in range(2000):\n'
     ' p = tempfile.mktemp(); open(p, \'w\').write(str(i)); os.stat(p); os.unlink(p)\n'
     'print(\'offline\', hashlib.sha256(b\'x\' * 50000000).hexdigest()[:8])"', 'offline '),
    ('alpine:3.20', [], 'apk add -q curl >/dev/null && curl -sI https://example.com | head -1', 'HTTP/'),
    ('debian:bookworm-slim', [], 'apt-get update -qq >/dev/null && apt-get install -y -qq tree >/dev/null '
     '&& tree -L 1 /etc | tail -1', 'directories'),
    ('python:3.13-slim', ['-w', '/app'], 'python -m venv v && v/bin/pip install -q requests '
     '&& v/bin/python -c "import requests; print(\'requests\', requests.__version__)"', 'requests '),
    ('node:lts-alpine', ['-w', '/app'], 'npm init -y >/dev/null && npm install --silent lodash '
     '&& node -e "console.log(\'lodash\', require(\'lodash\').VERSION)"', 'lodash '),
    # The images' own entrypoints: redis drops to its user with util-linux
    # setpriv (capabilities, PR_SET_KEEPCAPS) and listens on `*` and v6-only
    # `::`; nginx adds `listen [::]:80` next to `listen 80` and sets FIOASYNC
    # on its worker channels (refused by HarmonyOS, emulated: async_io.h).
    ('redis:7-alpine', [], 'docker-entrypoint.sh redis-server --daemonize yes >/dev/null '
     '&& for i in $(seq 50); do redis-cli ping 2>/dev/null | grep -q PONG && break; sleep 0.2; done; '
     'redis-cli set k v >/dev/null; echo redis $(redis-cli get k); redis-cli shutdown nosave', 'redis v'),
    ('nginx:alpine', [], '/docker-entrypoint.sh nginx >/dev/null 2>&1; '
     'wget -T 5 -qO- http://127.0.0.1/ | grep -o "Welcome to nginx"; wget -T 5 -qO- "http://[::1]/" | grep -c nginx; '
     'nginx -s quit', 'Welcome to nginx'),
    # Go: static binaries with their own svc instructions (clone child stack,
    # x28, goroutine stacks of a few KiB).
    ('golang:1.23-alpine', ['-w', '/app'], 'printf "package main\\nimport \\"fmt\\"\\n'
     'func main() { fmt.Println(\\"go\\", 6*7) }\\n" > main.go && go mod init demo 2>/dev/null; '
     'go build -o app . && ./app && go vet .', 'go 42'),
]


def docker(*args, **kwargs):
    return subprocess.run([sys.executable, '-B', str(DOCKER), *args], capture_output=True, text=True, **kwargs)


def timed(fn):
    began = time.time()
    result = fn()
    return result, time.time() - began


def direct(name, options, script):
    """docker create, then the container's loader argv run by hand."""
    import runtime
    import store
    p = docker('create', *options, '--entrypoint', '/bin/sh', name, '-c', script)
    cid = p.stdout.strip()
    st = store.Store()
    record = st.load_container(cid)
    argv, _ = runtime.command_line(st, record)
    try:
        return timed(lambda: subprocess.run(argv, cwd=str(runtime.rootfs_of(st, record)),
                                            capture_output=True, text=True, timeout=1800))
    finally:
        docker('rm', '-f', cid)


def main():
    only = sys.argv[1:]   # image names; "offline" for the offline workload only
    failures = 0
    rows = []
    for name, options, script, marker in WORKLOADS:
        if only and name not in only and not ('offline' in only and marker == 'offline '):
            continue
        if docker('image', 'inspect', name).returncode:
            p = docker('pull', '-q', name, timeout=3600)
            if p.returncode:
                print(f'SKIP: {name}: pull failed: {p.stderr.strip()[-200:]}')
                continue
        times = []
        for mode in ([], ['--isolate']):
            p, seconds = timed(lambda: docker('run', '--rm', *mode, *options, '--entrypoint', '/bin/sh',
                                              name, '-c', script, timeout=1800))
            ok = p.returncode == 0 and marker in p.stdout
            failures += not ok
            print(('PASS' if ok else 'FAIL') + f': {name} {" ".join(mode) or "plain"}: {seconds:.1f}s',
                  p.stdout.strip().splitlines()[-1:] if ok else p.stdout[-500:] + p.stderr[-800:])
            times.append(seconds)
        p, seconds = direct(name, options, script)
        ok = p.returncode == 0 and marker in p.stdout
        failures += not ok
        print(('PASS' if ok else 'FAIL') + f': {name} elfloader directly: {seconds:.1f}s',
              '' if ok else p.stdout[-300:] + p.stderr[-500:])
        rows.append((name, times[0], times[1], seconds))
    print('\n| image | docker run | docker run --isolate | elfloader on the same rootfs |')
    print('|---|---|---|---|')
    for name, plain, isolate, raw in rows:
        print(f'| {name} | {plain:.1f}s | {isolate:.1f}s | {raw:.1f}s |')
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
