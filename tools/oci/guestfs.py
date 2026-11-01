"""Container files from the host side: docker cp and the engine's archive
endpoints (docs/OCI.md).

Reading goes through the container's view: binds over the rootfs, or over
the merged view of a --cow container. A directory lists the names of every
layer that shows it, with whited-out names and those under an opaque
directory left out. A regular file of a layer image is filled before it is
read. A bind's destination shows its source, including a destination that
is not in the rootfs.

Writing starts from a directory FD of the destination. That FD is opened
one component at a time, with O_NOFOLLOW, from the root of the area that
holds the destination: the rootfs, the upper, or a bind's source. Each
entry is then created under its parent's FD without following links, so a
symlink the container left at a destination name is replaced, never
followed out of the container. In an upper, a whiteout of a written name is
removed, and a new directory over a whited-out one becomes opaque.

An entry is (parts, kind, mode, mtime, size, link, open). kind is one of:
'd' directory, 'f' regular file, 'l' symlink, 'h' hard link (link = parts
of its target in the same copy), or 'o' other (not copied). open() returns
a binary file object."""
import os
import stat
import tarfile
from collections import namedtuple
from pathlib import Path, PurePosixPath

import layers
import runspec
import union
import unpack
from store import StoreError
from unpack import DIR_FLAGS

Entry = namedtuple('Entry', 'parts kind mode mtime size link open')


def kind_of(mode):
    return 'd' if stat.S_ISDIR(mode) else 'l' if stat.S_ISLNK(mode) else 'f' if stat.S_ISREG(mode) else 'o'


def reader(host):
    return lambda: open(host, 'rb', opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW | os.O_CLOEXEC))


def entry(host, parts):
    st = os.lstat(host)
    kind = kind_of(st.st_mode)
    return Entry(list(parts), kind, stat.S_IMODE(st.st_mode), st.st_mtime, st.st_size,
                 os.readlink(host) if kind == 'l' else None, reader(host))


class View:
    """A container's files as its processes see them: view is a rootfs or
    (upper, lower); binds are (host source, guest destination)."""

    def __init__(self, view, binds):
        self.view = view
        self.binds = [(str(s), '/' + d.strip('/')) for s, d in binds]
        if isinstance(view, tuple):
            self.upper, self.lower = Path(view[0]), view[1]
            self.root = union.Root(*view)
        else:
            self.rootfs, self.root, self.upper = Path(view), None, None

    def resolve(self, path, follow=True):
        """Canonical parts of a guest path (symlinks resolved in the view)."""
        return runspec.guest_parts(self.view, self.binds, path, follow)

    def bind(self, parts):
        """(source, parts under it) of the bind holding parts, or None."""
        guest = '/' + '/'.join(parts)
        best = None
        for src, dst in self.binds:
            if guest == dst or dst == '/' or guest.startswith(dst + '/'):
                if best is None or len(dst) > len(best[1]):
                    best = (src, dst)
        if not best:
            return None
        return Path(best[0]), [p for p in guest[len(best[1]):].split('/') if p]

    def host(self, parts, fill=False):
        """(host path, whether the view shows it); fill: a layer image's
        file is filled first."""
        b = self.bind(parts)
        if b:
            host = b[0].joinpath(*b[1])
        elif self.root is None:
            host = self.rootfs.joinpath(*parts)
        else:
            host, layer = self.root.locate('/' + '/'.join(parts))
            if layer is None:
                return host, False
            if fill and layer:
                self.root.fill(host, layer)
        return host, os.path.lexists(host)

    def exists(self, parts):
        return self.host(parts)[1]

    def is_dir(self, parts):
        host, present = self.host(parts)
        if not present:
            return False
        b = self.bind(parts)
        if b and not b[1]:
            return os.path.isdir(host)   # (a bind's source may be a link on the host)
        return union.is_dir(host)

    def listdir(self, parts):
        b = self.bind(parts)
        if b:
            names = set(os.listdir(b[0].joinpath(*b[1])))
        elif self.root is None:
            names = set(os.listdir(self.rootfs.joinpath(*parts)))
        else:
            names = self.merged(parts)
        guest = '/' + '/'.join(parts)
        for _, dst in self.binds:
            d = PurePosixPath(dst)
            if d.name and str(d.parent) == guest:
                names.add(d.name)
        if not parts:
            names -= {p.lstrip('/') for p in layers.IGNORED}
        return sorted(names)

    def merged(self, parts):
        """Names of a --cow directory: every layer's, as the view shows them."""
        rel = '/'.join(parts)
        self.root.locate('/' + rel)    # (expands it in the layers that show it)
        names = set()
        for k, (layer, image) in enumerate(self.root.layers):
            p = layer.joinpath(*parts)
            if not union.is_dir(p):
                continue
            if image is not None:
                try:
                    self.root.expand(k, rel)
                except Exception:   # noqa: BLE001  (not a directory of that image)
                    continue
            names.update(n for n in os.listdir(p) if not union.marker(n))
        return {n for n in names if self.root.locate('/' + '/'.join(parts + [n]))[1] is not None}

    def walk(self, parts, top):
        """Entries of the tree at canonical parts, named top/...; top empty:
        the directory's contents only."""
        host, present = self.host(parts, fill=True)
        if not present:
            return
        try:
            e = entry(host, top)
        except FileNotFoundError:
            return
        if top:
            yield e
        if e.kind == 'd':
            for name in self.listdir(parts):
                yield from self.walk(parts + [name], top + [name])

    def open_dir(self, parts):
        """A directory FD to write into canonical guest directory parts (in a
        --cow container, the upper's, made as needed)."""
        b = self.bind(parts)
        if b:
            area, rest = b
        elif self.root is not None:
            union.mkdirs(self.upper, self.lower, '/' + '/'.join(parts))
            area, rest = self.upper, parts
        else:
            area, rest = self.rootfs, parts
        fd = os.open(area, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        root = unpack.Rootfs(fd=fd)
        try:
            return root.open_dir(rest)
        except OSError as e:
            raise StoreError(f'destination /{"/".join(parts)} changed while copying: {e}') from None
        finally:
            root.close()


def host_walk(path, top):
    """Entries of a host tree (symlinks copied as symlinks)."""
    e = entry(path, top)
    if top:
        yield e
    if e.kind == 'd':
        for name in sorted(os.listdir(path)):
            yield from host_walk(Path(path, name), top + [name])


def tar_walk(tar):
    """Entries of a tar stream (member names checked: relative, no ..)."""
    for m in tar:
        try:
            parts = list(unpack.clean_name(m.name))
        except unpack.UnpackError as e:
            raise StoreError(str(e)) from None
        if not parts:
            continue
        kind, link = 'o', None
        if m.isdir():
            kind = 'd'
        elif m.issym():
            kind, link = 'l', m.linkname
        elif m.islnk():
            try:
                kind, link = 'h', list(unpack.clean_name(m.linkname))
            except unpack.UnpackError as e:
                raise StoreError(str(e)) from None
        elif m.isreg():
            kind = 'f'
        yield Entry(parts, kind, m.mode & 0o7777, m.mtime, m.size, link, lambda m=m: tar.extractfile(m))


class TarSink:
    def __init__(self, tar):
        self.tar = tar

    def put(self, e):
        info = tarfile.TarInfo('/'.join(e.parts))
        info.mode, info.mtime = e.mode, int(e.mtime)
        if e.kind == 'd':
            info.type = tarfile.DIRTYPE
        elif e.kind == 'l':
            info.type, info.linkname = tarfile.SYMTYPE, e.link
        elif e.kind == 'f':
            with e.open() as f:
                info.size = os.fstat(f.fileno()).st_size
                self.tar.addfile(info, f)
            return
        else:
            return
        self.tar.addfile(info)

    def finish(self):
        pass


def set_mode(fd, mode, is_dir):
    wanted = unpack.host_mode(mode, is_dir)
    for drop in (0, 0o6000, 0o7000):   # setuid/setgid, sticky may be refused
        try:
            os.chmod(fd, wanted & ~drop)
            return
        except PermissionError:
            continue


class DirSink:
    """Writes entries under a directory FD (taken over), never following a
    link; upper: the directory is in a --cow container's upper."""

    def __init__(self, fd, upper=False):
        self.root = unpack.Rootfs(fd=fd)
        self.upper = upper
        self.dir_times = []

    def put(self, e):
        name = e.parts[-1]
        if self.upper and union.marker(name):
            raise StoreError(f'{"/".join(e.parts)}: a .wh. name cannot be written into a --cow container')
        if e.kind == 'o':
            return
        fd = self.root.parent(e.parts)
        try:
            self.write(fd, name, e)
        finally:
            os.close(fd)

    def write(self, fd, name, e):
        try:
            existing = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        is_dir = existing is not None and stat.S_ISDIR(existing.st_mode)
        if existing and not (e.kind == 'd' and is_dir):
            unpack.remove_tree(fd, name)
            is_dir = False
        whiteout = False
        if self.upper:
            try:
                os.unlink('.wh.' + name, dir_fd=fd)
                whiteout = True
            except FileNotFoundError:
                pass
        if e.kind == 'd':
            if not is_dir:
                os.mkdir(name, 0o700, dir_fd=fd)
            dfd = os.open(name, DIR_FLAGS, dir_fd=fd)
            try:
                if whiteout:   # what the whiteout hid stays hidden
                    os.close(os.open(union.OPAQUE, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=dfd))
                set_mode(dfd, e.mode, True)
            finally:
                os.close(dfd)
            self.dir_times.append((e.parts, e.mtime))
        elif e.kind == 'l':
            os.symlink(e.link, name, dir_fd=fd)
            try:
                os.utime(name, (e.mtime, e.mtime), dir_fd=fd, follow_symlinks=False)
            except OSError:
                pass
        else:
            if e.kind == 'h':
                try:
                    src = os.fdopen(self.root.open_file(e.link), 'rb')
                except OSError:
                    raise StoreError(f'hard link {"/".join(e.parts)} to missing {"/".join(e.link)}') from None
            else:
                src = e.open()
            with src:
                out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=fd)
                try:
                    while True:
                        chunk = src.read(1 << 20)
                        if not chunk:
                            break
                        os.write(out, chunk)
                    mode = stat.S_IMODE(os.fstat(src.fileno()).st_mode) if e.kind == 'h' else e.mode
                    set_mode(out, mode, False)
                    os.utime(out, (e.mtime, e.mtime))
                finally:
                    os.close(out)

    def finish(self):
        for parts, mtime in reversed(self.dir_times):
            try:
                fd = self.root.open_dir(parts)
            except OSError:
                continue
            try:
                os.utime(fd, (mtime, mtime))
            finally:
                os.close(fd)
        self.root.close()


def copy(entries, sink):
    try:
        for e in entries:
            sink.put(e)
    except (OSError, unpack.UnpackError) as e:
        raise StoreError(f'copy failed: {e}') from None
    finally:
        sink.finish()
