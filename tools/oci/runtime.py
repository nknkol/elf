"""Containers: create, start (foreground or supervised), stop, exec, cp, logs.

There is no daemon: a foreground `run`/`start -a` waits for its container
itself; `run -d`/`start` hand it to a small per-container monitor process
(`docker __monitor <id>`) that writes the log, records the exit code and
applies the restart policy (docs/OCI.md, R2). The container's processes are
one process group; its id and start time are recorded in run.json."""
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import runspec
import store as store_mod
from store import StoreError

TOOL = Path(__file__).resolve().parent / 'docker'


def proc_start_time(pid):
    try:
        data = Path(f'/proc/{pid}/stat').read_text()
    except OSError:
        return None
    return int(data.rsplit(')', 1)[1].split()[19])


def alive(state):
    pid = state.get('Pid') or 0
    return pid > 0 and proc_start_time(pid) == state.get('PidStart')


def refresh(st, record):
    """A record whose 'running' state outlived its process (the waiting
    docker or monitor process was killed) becomes 'exited'."""
    state = record['State']
    if state['Status'] in ('running', 'restarting') and not alive(state):
        monitor = state.get('MonitorPid') or 0
        if monitor and proc_start_time(monitor) == state.get('MonitorStart'):
            return record   # The monitor is restarting it.
        with st.lock():
            record = st.load_container(record['Id'])
            state = record['State']
            if state['Status'] in ('running', 'restarting') and not alive(state):
                state.update(Status='exited', Running=False, Pid=0,
                             FinishedAt=state.get('FinishedAt') or store_mod.now())
                if state.get('ExitCode') is None:
                    state['ExitCode'] = 255
                st.save_container(record)
    return record


def rootfs_of(st, record):
    if record['HostConfig'].get('ReadonlyRootfs') or record['HostConfig'].get('InPlace'):
        return st.image_dir(record['Image']) / 'rootfs'
    return st.container_dir(record['Id']) / 'rootfs'


def create(st, record, quiet=False):
    """Makes containers/<id>: rootfs copy (or none), etc files, run.json."""
    cid = record['Id']
    work = st.tmpdir('container')
    try:
        image_root = st.image_dir(record['Image']) / 'rootfs'
        host = record['HostConfig']
        if host.get('ReadonlyRootfs'):
            for name in ('tmp', 'run', 'var-tmp', 'workdir'):
                (work / 'writable' / name).mkdir(parents=True)
                (work / 'writable' / name).chmod(0o1777)
        elif host.get('InPlace'):
            with st.lock():
                info = store_mod.read_json(st.image_dir(record['Image']) / 'info.json', {})
                info['dirty'] = True
                store_mod.write_json(st.image_dir(record['Image']) / 'info.json', info)
        else:
            runspec.copy_rootfs(image_root, work / 'rootfs')
        runspec.write_etc(work, record['Config']['Hostname'], host.get('ExtraHosts') or [],
                          host.get('Dns') or [])
        for tmpfs in host.get('Tmpfs') or []:
            (work / 'tmpfs' / tmpfs.strip('/').replace('/', '_')).mkdir(parents=True, exist_ok=True)
        rootfs = image_root if host.get('ReadonlyRootfs') or host.get('InPlace') else work / 'rootfs'
        runspec.install_helper(rootfs)
        # Docker creates a missing working directory (not in a read-only root).
        cwd = record['Config'].get('WorkingDir')
        if cwd and not host.get('ReadonlyRootfs'):
            runspec.make_guest_dirs(rootfs, [(b[0], b[1]) for b in all_binds(st, record, work)], cwd)
        store_mod.write_json(work / 'run.json', record)
        with st.lock():
            if any(c['Name'] == record['Name'] for c in st.containers()):
                raise StoreError(f'Conflict. The container name "/{record["Name"]}" is already in use')
            work.rename(st.container_dir(cid))
    finally:
        if work.exists():
            store_mod.remove(work)
    return cid


def all_binds(st, record, cdir=None):
    """User binds plus the ones the record implies (read-only root's
    writable dirs, tmpfs dirs), as (host, guest, mode)."""
    cdir = cdir or st.container_dir(record['Id'])
    host = record['HostConfig']
    binds = []
    if host.get('ReadonlyRootfs'):
        binds += [(str(cdir / 'writable' / 'tmp'), '/tmp', 'rw'),
                  (str(cdir / 'writable' / 'run'), '/run', 'rw'),
                  (str(cdir / 'writable' / 'var-tmp'), '/var/tmp', 'rw')]
        # Docker creates a missing working directory; the root cannot
        # change, so an empty private directory stands in for it.
        cwd = record['Config'].get('WorkingDir')
        image_root = st.image_dir(record['Image']) / 'rootfs'
        if cwd and cwd not in ('/tmp', '/run', '/var/tmp') and \
                not runspec.guest_resolve(image_root, [], cwd).is_dir():
            binds.append((str(cdir / 'writable' / 'workdir'), cwd, 'rw'))
    for tmpfs in host.get('Tmpfs') or []:
        binds.append((str(cdir / 'tmpfs' / tmpfs.strip('/').replace('/', '_')), tmpfs, 'rw'))
    for b in host['Binds']:
        src = b[0]
        if not src.startswith('/'):
            src = str(st.create_volume(src))
        binds.append((src, b[1], b[2]))
    return binds


def command_line(st, record, **kwargs):
    cdir = st.container_dir(record['Id'])
    resolved = dict(record, HostConfig=dict(record['HostConfig'], Binds=all_binds(st, record)))
    return runspec.build(resolved, rootfs_of(st, record), cdir,
                         isolate=record['HostConfig'].get('Isolate'), **kwargs)


def set_state(st, cid, **fields):
    with st.lock():
        record = st.load_container(cid)
        record['State'].update(fields)
        st.save_container(record)
        return record


class Forwarder:
    """Signals for the docker process go to the container's main process
    (as Docker's sig-proxy); SIGTERM becomes the image's StopSignal."""

    def __init__(self, stop_signal):
        self.pgid = None
        self.stop_signal = stop_signal
        self.saved = {}

    def install(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT,
                    signal.SIGUSR1, signal.SIGUSR2, signal.SIGWINCH):
            self.saved[sig] = signal.signal(sig, self.forward)

    def forward(self, sig, frame):
        if self.pgid:
            try:
                os.kill(self.pgid, self.stop_signal if sig == signal.SIGTERM else sig)
            except ProcessLookupError:
                pass

    def restore(self):
        for sig, handler in self.saved.items():
            signal.signal(sig, handler)


def parse_signal(name):
    if not name:
        return signal.SIGTERM
    name = str(name).upper()
    if name.isdigit():
        return signal.Signals(int(name))
    if not name.startswith('SIG'):
        name = 'SIG' + name
    try:
        return signal.Signals[name]
    except KeyError:
        raise StoreError(f'invalid signal: {name}') from None


def spawn(argv, env_path, stdin, stdout, stderr, cwd, foreground_tty):
    """Starts the loader in a new process group (the container's)."""
    def child():
        os.setpgid(0, 0)
        if foreground_tty is not None:
            signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            os.tcsetpgrp(foreground_tty, os.getpgrp())
            signal.signal(signal.SIGTTOU, signal.SIG_DFL)
    return subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr, cwd=cwd,
                            env={'PATH': env_path}, preexec_fn=child, close_fds=True)


def run_once(st, record, stdio, interactive, tty):
    """One run of the container in this process; returns its exit code."""
    cid = record['Id']
    argv, _ = command_line(st, record)
    rootfs = rootfs_of(st, record)
    runspec.install_helper(rootfs)
    stdin, stdout, stderr = stdio
    terminal = None
    if (interactive or tty) and os.isatty(0) and stdin is None:
        terminal = 0
    forwarder = Forwarder(parse_signal(record['Config'].get('StopSignal')))
    forwarder.install()
    try:
        proc = spawn(argv, os.environ.get('PATH', '/usr/bin:/bin'), stdin, stdout, stderr,
                     str(rootfs), terminal)
    except BaseException:
        forwarder.restore()
        raise
    forwarder.pgid = proc.pid
    set_state(st, cid, Status='running', Running=True, Pid=proc.pid,
              PidStart=proc_start_time(proc.pid), StartedAt=store_mod.now(), ExitCode=None,
              FinishedAt=None)
    try:
        while True:
            try:
                code = proc.wait()
                break
            except InterruptedError:
                continue
    finally:
        forwarder.restore()
        # The main process is gone: the rest of the container goes too, as
        # when a PID namespace's init exits.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        if terminal is not None:
            old = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            try:
                os.tcsetpgrp(terminal, os.getpgrp())
            except OSError:
                pass
            signal.signal(signal.SIGTTOU, old)
    if code < 0:
        code = 128 - code
    return code


def finish(st, cid, code):
    with st.lock():
        record = st.load_container(cid)
        record['State'].update(Status='exited', Running=False, Pid=0, ExitCode=code,
                               FinishedAt=store_mod.now())
        st.save_container(record)
    return record


def start_foreground(st, record, interactive, tty):
    stdin = None if interactive else subprocess.DEVNULL
    code = run_once(st, record, (stdin, None, None), interactive, tty)
    record = finish(st, record['Id'], code)
    if record['HostConfig'].get('AutoRemove'):
        remove(st, record, force=True)
    return code


def start_detached(st, record):
    """Hands the container to its monitor; returns once it runs."""
    cid = record['Id']
    set_state(st, cid, Status='restarting', Running=False, ManualStop=False, ExitCode=None)
    proc = subprocess.Popen([sys.executable, '-B', str(TOOL), '__monitor', cid],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                            env=dict(os.environ, ELF_OCI_HOME=str(st.home)))
    deadline = time.time() + 30
    while time.time() < deadline:
        record = st.load_container(cid)
        if record['State']['Status'] != 'restarting' or record['State'].get('Pid'):
            break
        if proc.poll() is not None:
            break
        time.sleep(0.02)
    return record


def monitor(st, cid):
    """`__monitor`: the supervising process of a detached container."""
    record = st.load_container(cid)
    set_state(st, cid, MonitorPid=os.getpid(), MonitorStart=proc_start_time(os.getpid()))
    policy = record['HostConfig'].get('RestartPolicy') or {'Name': 'no'}
    restarts = 0
    delay = 0.1
    log = open(st.container_dir(cid) / 'log', 'ab', buffering=0)
    while True:
        began = time.time()
        try:
            code = run_once(st, st.load_container(cid), (subprocess.DEVNULL, log, log), False, False)
        except Exception as e:   # A start failure is the container's exit.
            log.write(f'docker: {e}\n'.encode())
            code = 125
        record = finish(st, cid, code)
        name = policy.get('Name', 'no')
        manual = record['State'].get('ManualStop')
        again = not manual and (name in ('always', 'unless-stopped') or
                                (name == 'on-failure' and code != 0 and
                                 (not policy.get('MaximumRetryCount') or
                                  restarts < policy['MaximumRetryCount'])))
        if not again:
            break
        restarts += 1
        delay = 0.1 if time.time() - began > 10 else min(delay * 2, 60)
        set_state(st, cid, Status='restarting', RestartCount=restarts)
        time.sleep(delay)
        if st.load_container(cid)['State'].get('ManualStop'):
            finish(st, cid, code)
            break
    set_state(st, cid, MonitorPid=0)
    if record['HostConfig'].get('AutoRemove'):
        remove(st, st.load_container(cid), force=True)


def stop(st, record, timeout=None, sig=None):
    """Stop signal, then SIGKILL after the timeout; no restart afterwards."""
    cid = record['Id']
    record = set_state(st, cid, ManualStop=True)
    state = record['State']
    if not alive(state):
        return refresh(st, record)
    pgid = state['Pid']
    sig = sig or parse_signal(record['Config'].get('StopSignal'))
    if timeout is None:
        timeout = record['Config'].get('StopTimeout') or 10
    try:
        os.kill(pgid, sig)   # The main process, as Docker.
    except ProcessLookupError:
        pass
    deadline = time.time() + timeout
    while time.time() < deadline and alive(state):
        time.sleep(0.05)
    if alive(state):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    # The waiting process (foreground run or monitor) records the exit.
    deadline = time.time() + 5
    while time.time() < deadline:
        record = st.load_container(cid)
        if record['State']['Status'] == 'exited':
            return record
        if not alive(record['State']) and not (record['State'].get('MonitorPid') and proc_start_time(
                record['State']['MonitorPid']) == record['State'].get('MonitorStart')):
            break
        time.sleep(0.05)
    return refresh(st, st.load_container(cid))


def kill(st, record, sig):
    state = refresh(st, record)['State']
    if not alive(state):
        raise StoreError(f'Container {record["Id"][:12]} is not running')
    if sig in (signal.SIGKILL, signal.SIGTERM, signal.SIGINT):
        set_state(st, record['Id'], ManualStop=True)
    os.kill(state['Pid'], sig)


def wait(st, record):
    cid = record['Id']
    while True:
        record = refresh(st, st.load_container(cid))
        if record['State']['Status'] in ('exited', 'created'):
            return record['State'].get('ExitCode') or 0
        time.sleep(0.1)


def remove(st, record, force=False, volumes=False):
    record = refresh(st, record)
    if record['State']['Status'] in ('running', 'restarting'):
        if not force:
            raise StoreError(f'cannot remove container "/{record["Name"]}": container is running: '
                             'stop the container before removing or force remove')
        stop(st, record, timeout=0, sig=signal.SIGKILL)
    cdir = st.container_dir(record['Id'])
    if cdir.exists():
        trash = st.home / 'tmp' / f'rm-{record["Id"]}'
        with st.lock():
            cdir.rename(trash)
        store_mod.remove(trash)


def exec_in(st, record, command, interactive, tty, detach, env, workdir, user):
    record = refresh(st, record)
    if record['State']['Status'] != 'running':
        raise StoreError(f'Container {record["Id"][:12]} is not running')
    argv, _ = command_line(st, record, extra_env=env, workdir=workdir, user=user, command=command)
    rootfs = rootfs_of(st, record)
    if detach:
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, cwd=str(rootfs), start_new_session=True)
        return 0
    terminal = 0 if (interactive or tty) and os.isatty(0) else None
    forwarder = Forwarder(signal.SIGTERM)
    forwarder.install()
    try:
        proc = spawn(argv, os.environ.get('PATH', '/usr/bin:/bin'),
                     None if interactive else subprocess.DEVNULL, None, None, str(rootfs), terminal)
        forwarder.pgid = proc.pid
        code = proc.wait()
    finally:
        forwarder.restore()
        if terminal is not None:
            old = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
            try:
                os.tcsetpgrp(terminal, os.getpgrp())
            except OSError:
                pass
            signal.signal(signal.SIGTTOU, old)
    return 128 - code if code < 0 else code


def container_path(st, record, path, follow=True):
    binds = [(b[0], b[1]) for b in all_binds(st, record)]
    return runspec.guest_resolve(rootfs_of(st, record), binds, path, follow)


def cp(st, src, dest, archive_mode=False):
    """docker cp: exactly one side is CONTAINER:PATH; '-' is a tar stream."""
    def split(spec):
        if spec == '-' or spec.startswith(('/', '.')) or ':' not in spec:
            return None, spec
        name, _, path = spec.partition(':')
        return st.resolve_container(name), path

    (src_c, src_path), (dest_c, dest_path) = split(src), split(dest)
    if bool(src_c) == bool(dest_c):
        raise StoreError('copying between containers or between local paths is not supported')
    if src_c:
        host_src = container_path(st, src_c, src_path, follow=True)
        if not host_src.exists() and not host_src.is_symlink():
            raise StoreError(f'Could not find the file {src_path} in container {src_c["Name"]}')
        if dest_path == '-':
            with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as tar:
                tar.add(str(host_src), arcname=Path(src_path.rstrip('/')).name or '.')
            return
        copy_tree(host_src, Path(dest_path), src_path)
    else:
        host_dest = container_path(st, dest_c, dest_path)
        if src_path == '-':
            if not host_dest.is_dir():
                raise StoreError(f'destination "{dest_path}" must be a directory')
            import unpack
            extractor = unpack.Extractor(host_dest)
            try:
                with tarfile.open(fileobj=sys.stdin.buffer, mode='r|') as tar:
                    touched, times = set(), []
                    for member in tar:
                        extractor.member(tar, member, touched, times)
            finally:
                extractor.close()
            return
        copy_tree(Path(src_path), host_dest, src_path)


def copy_tree(src, dest, src_spec):
    """Docker's cp rules: into an existing directory under the source's
    name, otherwise as dest; "src/." copies the contents."""
    contents = src_spec.endswith('/.')
    if src.is_dir() and not src.is_symlink():
        if dest.exists() and not dest.is_dir():
            raise StoreError('cannot copy a directory to a file')
        target = dest if contents or not dest.exists() else dest / src.name
        shutil.copytree(src, target, symlinks=True, dirs_exist_ok=True)
    else:
        if src_spec.endswith('/'):
            raise StoreError(f'{src_spec} is not a directory')
        target = dest / src.name if dest.is_dir() else dest
        if src.is_symlink():
            if target.is_symlink() or target.exists():
                target.unlink()
            os.symlink(os.readlink(src), target)
        else:
            shutil.copy2(src, target)


def logs(st, record, follow=False, tail=None):
    path = st.container_dir(record['Id']) / 'log'
    if not path.exists():
        return
    with open(path, 'rb') as f:
        if tail is not None:
            lines = f.read().splitlines(keepends=True)
            sys.stdout.buffer.write(b''.join(lines[-tail:] if tail else []))
        else:
            shutil.copyfileobj(f, sys.stdout.buffer)
        sys.stdout.flush()
        while follow:
            chunk = f.read(65536)
            if chunk:
                sys.stdout.buffer.write(chunk)
                sys.stdout.flush()
                continue
            record = refresh(st, st.load_container(record['Id']))
            if record['State']['Status'] not in ('running', 'restarting'):
                rest = f.read()
                sys.stdout.buffer.write(rest)
                sys.stdout.flush()
                return
            time.sleep(0.2)
