"""Image config + run options -> elfloader argv (docs/OCI.md, "配置映射")."""
import os
import shutil
import stat
from pathlib import Path, PurePosixPath

import unpack

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / 'build'
HELPER = '.elf-exec'
DEFAULT_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
DEVICES = ('/dev/null', '/dev/zero', '/dev/full', '/dev/random', '/dev/urandom',
           '/dev/tty', '/dev/ptmx')
MAX_PATH = 255  # CONFIG_MAX_PATH including NUL


class SpecError(Exception):
    pass


def loader_path(guarded):
    env = os.environ.get('ELF_LOADER_GUARDED' if guarded else 'ELF_LOADER')
    path = Path(env) if env else BUILD / ('elfloader-guarded' if guarded else 'elfloader')
    if not path.exists():
        raise SpecError(f'{path} not found: run make build (or set ELF_LOADER)')
    return path


def helper_path():
    path = Path(os.environ.get('ELF_EXEC_HELPER') or BUILD / 'elf-exec-helper')
    if not path.exists():
        raise SpecError(f'{path} not found: run make build')
    return path


def install_helper(rootfs):
    """The first guest program lives in the rootfs: the loader opens the
    initial program relative to the root, not through binds."""
    src = helper_path()
    dest = Path(rootfs) / HELPER
    try:
        if dest.read_bytes() == src.read_bytes():
            return
    except OSError:
        pass
    tmp = dest.with_name(HELPER + '.tmp')
    shutil.copy2(src, tmp)
    os.chmod(tmp, 0o755)
    tmp.replace(dest)


def read_guest_file(rootfs, guest_path):
    """A rootfs file read without following any symlink (None if absent).
    rootfs may be (upper, lower) of a --cow container (R6)."""
    if isinstance(rootfs, tuple):
        import union
        view = union.Root(*rootfs)
        host, layer = view.locate('/' + guest_path.lstrip('/'))
        if layer is None:
            return None
        view.fill(host, layer)  # a layer image's file (R6)
        rootfs = view.layers[layer][0]
    root = unpack.Rootfs(rootfs)
    try:
        fd = root.open_file(unpack.clean_name(guest_path.lstrip('/')))
    except OSError:
        return None
    finally:
        root.close()
    with os.fdopen(fd, 'rb') as f:
        return f.read(1 << 20).decode(errors='replace')


def resolve_user(rootfs, user):
    """Docker's -u: name|uid[:group|gid] -> (uid, gid, home)."""
    if not user:
        user = 'root'
    name, _, group = user.partition(':')
    passwd = [line.split(':') for line in (read_guest_file(rootfs, '/etc/passwd') or '').splitlines()
              if line.count(':') >= 6]
    groups = [line.split(':') for line in (read_guest_file(rootfs, '/etc/group') or '').splitlines()
              if line.count(':') >= 3]
    uid = gid = None
    home = '/'
    for entry in passwd:
        if entry[0] == name or (name.isdigit() and entry[2] == name):
            uid, gid, home = int(entry[2]), int(entry[3]), entry[5] or '/'
            break
    if uid is None:
        if not name.isdigit():
            raise SpecError(f'unable to find user {name}: no matching entries in passwd file')
        uid, gid = int(name), 0
    if group:
        if group.isdigit():
            gid = int(group)
        else:
            match = [g for g in groups if g[0] == group]
            if not match:
                raise SpecError(f'unable to find group {group}: no matching entries in group file')
            gid = int(match[0][2])
    if uid == 0 and home == '/':
        home = '/root'
    return uid, gid, home


def guest_resolve(rootfs, binds, path, follow=True):
    """Host path of a guest path: symlinks resolved inside the container view
    (absolute targets restart at the container root), binds applied."""
    def host_of(parts):
        guest = '/' + '/'.join(parts)
        best = None
        for src, dst in binds:
            if guest == dst or guest.startswith(dst.rstrip('/') + '/'):
                if best is None or len(dst) > len(best[1]):
                    best = (src, dst)
        if best:
            rest = guest[len(best[1]):].lstrip('/')
            return Path(best[0], rest) if rest else Path(best[0])
        if isinstance(rootfs, tuple):  # (upper, lower) of a --cow container
            import union
            return union.Root(*rootfs).locate(guest)[0]
        return Path(rootfs, *parts)

    parts = []
    pending = [p for p in PurePosixPath('/' + path.lstrip('/')).parts[1:]]
    links = 0
    while pending:
        name = pending.pop(0)
        if name in ('', '.'):
            continue
        if name == '..':
            if parts:
                parts.pop()
            continue
        candidate = parts + [name]
        host = host_of(candidate)
        if (pending or follow) and host.is_symlink():
            links += 1
            if links > 40:
                raise SpecError(f'too many levels of symbolic links: {path}')
            target = os.readlink(host)
            if target.startswith('/'):
                parts = []
            pending = [p for p in PurePosixPath(target).parts if p != '/'] + pending
            continue
        parts = candidate
    return host_of(parts)


def make_guest_dirs(rootfs, binds, path):
    host = guest_resolve(rootfs, binds, path)
    host.mkdir(parents=True, exist_ok=True)


def build(record, rootfs, cdir, isolate=False, extra_env=(), workdir=None, user=None,
          command=None, lower=None):
    """The elfloader argv of a container start (or exec) and its cwd."""
    cfg, host = record['Config'], record['HostConfig']
    binds = [tuple(b) for b in host['Binds']]     # (host, guest, 'ro'|'rw')
    ro_root = host.get('ReadonlyRootfs')
    guarded = ro_root or any(mode == 'ro' for _, _, mode in binds)
    loader = loader_path(guarded)
    uid, gid, home = resolve_user((rootfs, lower) if lower else rootfs,
                                  user if user is not None else cfg.get('User'))
    env = {}
    for entry in cfg.get('Env') or []:
        key, _, value = entry.partition('=')
        env[key] = value
    for entry in extra_env:
        key, _, value = entry.partition('=')
        env[key] = value
    env.setdefault('PATH', DEFAULT_PATH)
    env.setdefault('HOSTNAME', cfg['Hostname'])
    env.setdefault('HOME', home)
    if cfg.get('Tty'):
        env.setdefault('TERM', os.environ.get('TERM', 'xterm'))
    cwd = workdir or cfg.get('WorkingDir') or '/'
    if not cwd.startswith('/'):
        raise SpecError(f'the working directory {cwd} is invalid: it needs to be an absolute path')
    all_binds = [('/proc', '/proc', 'rw')]
    if os.path.isdir('/sys'):
        all_binds.append(('/sys', '/sys', 'ro'))
    for dev in DEVICES:
        if os.path.exists(dev):
            all_binds.append((dev, dev, 'rw'))
    # An inherited terminal: its /dev/pts/N (tty, stty, ttyname need it;
    # the host does not let the app list /dev/pts itself).
    for fd in (0, 1, 2):
        try:
            name = os.ttyname(fd)
        except OSError:
            continue
        if name.startswith('/dev/') and all(b[1] != name for b in all_binds):
            all_binds.append((name, name, 'rw'))
    etc = cdir / 'etc'
    all_binds += [(str(etc / 'hosts'), '/etc/hosts', 'rw'),
                  (str(etc / 'hostname'), '/etc/hostname', 'rw'),
                  (str(etc / 'resolv.conf'), '/etc/resolv.conf', 'rw'),
                  (str(cdir / 'shm'), '/dev/shm', 'rw')]
    all_binds += binds
    argv = [str(loader)]
    if isolate:
        argv.append('--isolate')
        for device in host.get('IsolateDevices') or []:
            argv += ['--isolate-device', device]
    argv += ['--mode', 'container', '--root', str(rootfs), '--link-copy']
    if lower:
        import union
        # R6: the shared image rootfs, or the image's layer images.
        for cache, image in union.lowers(lower):
            argv += ['--lower', str(cache)] + (['--lower-image', str(image)] if image else [])
    # Mounts the container makes (R4): a table every process of it shares
    # (docker exec joins it through the file), tmpfs directories below.
    argv += ['--mount-table', str(cdir / 'mounts.table'), '--mount-scratch', str(cdir / 'mounts')]
    if host.get('Owners'):
        argv += ['--owner-db', str(cdir / 'owners.db')]
    vector = 'r' if ro_root else 'w'
    for src, dst, mode in all_binds:
        if ':' in src or ':' in dst:
            raise SpecError(f'volume paths cannot contain ":": {src}:{dst}')
        argv += ['-v', f'{src}:{dst}']
        vector += 'r' if mode == 'ro' else 'w'
    if guarded:
        argv += ['--guard-path-mutations', vector]
    argv += ['--cwd', cwd, '--user', f'{uid}:{gid}', '--hostname', cfg['Hostname'][:64]]
    for key, value in env.items():
        argv += ['-e', f'{key}={value}']
    if len(str(cdir / 'mounts').encode()) >= MAX_PATH - 48:
        raise SpecError(f'the container directory path is too long for the loader: {cdir}')
    import union
    layer_paths = [str(p) for entry in (union.lowers(lower) if lower else []) for p in entry if p]
    for value in [str(rootfs), *layer_paths, cwd, *(p for b in all_binds for p in b[:2])]:
        if len(value.encode()) >= MAX_PATH:
            raise SpecError(f'path exceeds the loader limit of {MAX_PATH - 1} bytes: {value[:80]}...')
    if command is None:
        command = (cfg.get('Entrypoint') or []) + (cfg.get('Cmd') or [])
    if not command:
        raise SpecError('no command specified')
    argv += ['--', f'./{HELPER}', cwd, command[0], *command]
    return argv, env


def write_etc(cdir, hostname, extra_hosts=(), dns=()):
    etc = cdir / 'etc'
    etc.mkdir(parents=True, exist_ok=True)
    (cdir / 'shm').mkdir(exist_ok=True)
    (etc / 'hostname').write_text(hostname + '\n')
    hosts = ['127.0.0.1\tlocalhost', '::1\tlocalhost ip6-localhost ip6-loopback',
             f'127.0.1.1\t{hostname}']
    hosts += [f'{ip}\t{name}' for name, ip in extra_hosts]
    (etc / 'hosts').write_text('\n'.join(hosts) + '\n')
    if dns:
        resolv = ''.join(f'nameserver {d}\n' for d in dns)
    else:
        try:
            resolv = Path('/etc/resolv.conf').read_text()
        except OSError:
            resolv = ''
        if 'nameserver' not in resolv:
            resolv = 'nameserver 8.8.8.8\n'
    (etc / 'resolv.conf').write_text(resolv)


def copy_rootfs(src, dest):
    """A container's private copy of the image rootfs (metadata kept)."""
    def copy(s, d):
        st = os.lstat(s)
        if stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(s), d)
            os.utime(d, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)
        elif stat.S_ISDIR(st.st_mode):
            os.mkdir(d, 0o700)
            with os.scandir(s) as it:
                for entry in it:
                    copy(entry.path, os.path.join(d, entry.name))
            os.chmod(d, stat.S_IMODE(st.st_mode))
            os.utime(d, ns=(st.st_atime_ns, st.st_mtime_ns))
        elif stat.S_ISREG(st.st_mode):
            shutil.copyfile(s, d, follow_symlinks=False)
            os.chmod(d, stat.S_IMODE(st.st_mode))
            os.utime(d, ns=(st.st_atime_ns, st.st_mtime_ns))
    copy(str(src), str(dest))
