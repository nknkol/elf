"""Layer extraction into a rootfs (docs/OCI.md, "展开").

Every write starts from the rootfs directory FD and opens each parent with
O_NOFOLLOW, so no member (and no symlink left by an earlier layer) can make
a write land outside the rootfs. Symlinks are created verbatim: their
targets are guest paths. The host cannot hard-link or chown: a hard link to
an executable becomes a symlink to it (same program, same argv[0], shared
content), any other hard link a copy; owners are recorded in the metadata,
not applied."""
import errno
import hashlib
import io
import os
import stat
import tarfile
from pathlib import PurePosixPath

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
WHITEOUT = '.wh.'
OPAQUE = '.wh..wh..opq'
MAX_BYTES = int(os.environ.get('ELF_OCI_MAX_BYTES', 8 << 30))
MAX_ENTRIES = int(os.environ.get('ELF_OCI_MAX_ENTRIES', 1_000_000))
# Hard links to executables become symlinks to the target (busybox-style
# images have hundreds); "copy" copies every hard link.
HARDLINKS = os.environ.get('ELF_OCI_HARDLINKS', 'symlink-executables')


class UnpackError(Exception):
    pass


class HashingReader(io.RawIOBase):
    """Passes reads through and hashes them (diff_id of the plain tar)."""

    def __init__(self, raw):
        self.raw, self.hash = raw, hashlib.sha256()

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.raw.read(len(buffer))
        self.hash.update(data)
        buffer[:len(data)] = data
        return len(data)

    def drain(self):
        while self.read(1 << 20):
            pass
        return 'sha256:' + self.hash.hexdigest()


def open_layer(path):
    """A file object of the plain tar: gzip, zstd or uncompressed by magic."""
    f = open(path, 'rb')
    magic = f.read(4)
    f.seek(0)
    if magic[:2] == b'\x1f\x8b':
        import gzip
        return gzip.GzipFile(fileobj=f, mode='rb')
    if magic == b'\x28\xb5\x2f\xfd':
        try:
            from compression import zstd
        except ImportError:
            raise UnpackError('zstd layer needs Python 3.14 (compression.zstd)') from None
        return zstd.ZstdFile(f, mode='rb')
    return f


def clean_name(name):
    """Validated relative parts of a member name; () for the root itself."""
    path = PurePosixPath(name)
    if path.is_absolute() or name.startswith('/'):
        raise UnpackError(f'absolute path in layer: {name}')
    parts = [p for p in path.parts if p not in ('.', '')]
    if '..' in parts:
        raise UnpackError(f'path with .. in layer: {name}')
    return tuple(parts)


class Rootfs:
    """A directory written only through FDs opened without following links."""

    def __init__(self, path):
        self.fd = os.open(path, DIR_FLAGS)

    def close(self):
        os.close(self.fd)

    def parent(self, parts, create=True):
        """FD of the directory holding parts[-1]; parents are created 0755."""
        fd = os.dup(self.fd)
        try:
            for name in parts[:-1]:
                try:
                    next_fd = os.open(name, DIR_FLAGS, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(name, 0o755, dir_fd=fd)
                    next_fd = os.open(name, DIR_FLAGS, dir_fd=fd)
                except OSError as e:
                    if e.errno in (errno.ELOOP, errno.ENOTDIR):
                        if not create:
                            raise FileNotFoundError(name) from None
                        # A file or symlink where a directory is needed: the
                        # layer replaces it (never followed).
                        remove_tree(fd, name)
                        os.mkdir(name, 0o755, dir_fd=fd)
                        next_fd = os.open(name, DIR_FLAGS, dir_fd=fd)
                    else:
                        raise
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def open_dir(self, parts):
        """FD of an existing directory (no links followed)."""
        if not parts:
            return os.dup(self.fd)
        fd = self.parent(parts, create=False)
        try:
            return os.open(parts[-1], DIR_FLAGS, dir_fd=fd)
        finally:
            os.close(fd)

    def open_file(self, parts):
        """Read FD of an existing regular file (no links followed)."""
        fd = self.parent(parts, create=False)
        try:
            return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        finally:
            os.close(fd)


def remove_tree(dir_fd, name):
    """Removes name under dir_fd recursively, never following symlinks."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(st.st_mode):
        os.unlink(name, dir_fd=dir_fd)
        return
    fd = os.open(name, DIR_FLAGS, dir_fd=dir_fd)
    try:
        os.chmod(fd, 0o700 | stat.S_IMODE(st.st_mode))  # Removable children.
        for child in os.listdir(fd):
            remove_tree(fd, child)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=dir_fd)


def host_mode(mode, is_dir):
    """What the host gets: the owner (the fake root) can always write."""
    return (mode & 0o7777) | (0o700 if is_dir else 0o600)


class Extractor:
    def __init__(self, root_path):
        self.root = Rootfs(root_path)
        self.bytes = 0
        self.entries = 0
        # Recorded for R5 / inspection: guest metadata the host cannot hold.
        self.meta = {'owners': {}, 'modes': {}, 'hardlinks': {}, 'skipped': {}}

    def close(self):
        self.root.close()

    def layer(self, path):
        """Applies one layer; returns the diff_id of its plain tar."""
        raw = open_layer(path)
        reader = HashingReader(raw)
        buffered = io.BufferedReader(reader, 1 << 20)
        touched = set()
        dir_times = []
        try:
            with tarfile.open(fileobj=buffered, mode='r|') as tar:
                for member in tar:
                    self.member(tar, member, touched, dir_times)
            while buffered.read(1 << 20):
                pass
        except (tarfile.TarError, EOFError, OSError, ValueError) as e:
            if isinstance(e, UnpackError):
                raise
            raise UnpackError(f'{path}: {e}') from None
        finally:
            raw.close()
        for parts, mtime in reversed(dir_times):
            try:
                fd = self.root.open_dir(parts)
            except OSError:
                continue
            try:
                os.utime(fd, (mtime, mtime))
            finally:
                os.close(fd)
        return 'sha256:' + reader.hash.hexdigest()

    def member(self, tar, m, touched, dir_times):
        self.entries += 1
        if self.entries > MAX_ENTRIES:
            raise UnpackError(f'more than {MAX_ENTRIES} entries')
        parts = clean_name(m.name)
        if not parts:
            if m.isdir():
                os.chmod(self.root.fd, host_mode(m.mode, True))
            return
        name = parts[-1]
        key = '/' + '/'.join(parts)
        if name == OPAQUE:
            dir_parts = parts[:-1]
            try:
                fd = self.root.open_dir(dir_parts)
            except OSError:
                return
            try:
                self.purge(fd, '/' + '/'.join(dir_parts) if dir_parts else '', touched)
            finally:
                os.close(fd)
            return
        if name.startswith(WHITEOUT):
            target = name[len(WHITEOUT):]
            if not target or target in ('.', '..'):
                raise UnpackError(f'bad whiteout {m.name}')
            try:
                fd = self.root.parent(parts, create=False)
            except OSError:
                return
            try:
                remove_tree(fd, target)
            finally:
                os.close(fd)
            return
        touched.add(key)
        if m.uid or m.gid:
            self.meta['owners'][key] = [m.uid, m.gid]
        if m.ischr() or m.isblk() or m.isfifo():
            self.meta['skipped'][key] = 'device' if not m.isfifo() else 'fifo'
            return
        fd = self.root.parent(parts)
        try:
            self.write(tar, m, fd, name, parts, key, dir_times)
        finally:
            os.close(fd)

    def purge(self, dir_fd, prefix, touched):
        """Opaque directory: everything not written by this layer goes."""
        for child in os.listdir(dir_fd):
            key = f'{prefix}/{child}'
            if key not in touched:
                remove_tree(dir_fd, child)
                continue
            st = os.stat(child, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                fd = os.open(child, DIR_FLAGS, dir_fd=dir_fd)
                try:
                    self.purge(fd, key, touched)
                finally:
                    os.close(fd)

    def write(self, tar, m, fd, name, parts, key, dir_times):
        try:
            existing = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing and not (m.isdir() and stat.S_ISDIR(existing.st_mode)):
            remove_tree(fd, name)
        mode = m.mode & 0o7777
        if host_mode(mode, m.isdir()) != mode:
            self.meta['modes'][key] = mode
        if m.isdir():
            if not existing or not stat.S_ISDIR(existing.st_mode):
                os.mkdir(name, 0o700, dir_fd=fd)
            dfd = os.open(name, DIR_FLAGS, dir_fd=fd)
            try:
                self.chmod(dfd, mode, True, key)
            finally:
                os.close(dfd)
            dir_times.append((parts, m.mtime))
        elif m.issym():
            os.symlink(m.linkname, name, dir_fd=fd)
            os.utime(name, (m.mtime, m.mtime), dir_fd=fd, follow_symlinks=False)
        elif m.islnk():
            target = clean_name(m.linkname)
            try:
                src = self.root.open_file(target)
            except OSError:
                raise UnpackError(f'hard link {m.name} to missing {m.linkname}') from None
            try:
                st = os.fstat(src)
                if not stat.S_ISREG(st.st_mode):
                    raise UnpackError(f'hard link {m.name} to non-file {m.linkname}')
                if HARDLINKS != 'copy' and st.st_mode & 0o111:
                    os.symlink('/' + '/'.join(target), name, dir_fd=fd)
                    self.meta['hardlinks'][key] = '/' + '/'.join(target)
                    return
                self.count(st.st_size)
                out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                              os.O_CLOEXEC, 0o600, dir_fd=fd)
                try:
                    while os.sendfile(out, src, None, 1 << 24) > 0:
                        pass
                    self.chmod(out, stat.S_IMODE(st.st_mode), False, key)
                    os.utime(out, (st.st_mtime, st.st_mtime))
                finally:
                    os.close(out)
            finally:
                os.close(src)
            self.meta['hardlinks'][key] = '/' + '/'.join(target)
        elif m.isreg():
            self.count(m.size)
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                          os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                src = tar.extractfile(m)
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    os.write(out, chunk)
                self.chmod(out, mode, False, key)
                os.utime(out, (m.mtime, m.mtime))
            finally:
                os.close(out)
        else:
            self.meta['skipped'][key] = f'type {m.type!r}'

    def chmod(self, fd, mode, is_dir, key):
        wanted = host_mode(mode, is_dir)
        # setuid/setgid, then sticky, may be refused by the host: the guest
        # mode stays in the metadata.
        for drop in (0, 0o6000, 0o7000):
            try:
                os.chmod(fd, wanted & ~drop)
            except PermissionError:
                continue
            if drop:
                self.meta['modes'][key] = mode
            return
        raise UnpackError(f'cannot set mode of {key}')

    def count(self, size):
        self.bytes += size
        if self.bytes > MAX_BYTES:
            raise UnpackError(f'image exceeds {MAX_BYTES} bytes')
