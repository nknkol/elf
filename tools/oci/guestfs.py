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
import io
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


def open_root(path):
    """An area's root (the rootfs, a layer, a bind's source: the host's own
    paths, followed); a bind of a single file opens the file."""
    try:
        return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except NotADirectoryError:
        return os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)


def open_parent(root, rel):
    """FD of the directory holding rel[-1], each component opened from the
    area's root with O_NOFOLLOW (a link swapped in fails, ELOOP/ENOTDIR)."""
    fd = open_root(root)
    try:
        for name in rel[:-1]:
            nxt = os.open(name, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def entry_at(root, rel, parts):
    """(Entry, fd) of rel under an area's root: a directory or file is
    opened (never through a link) and described by fstat of that FD, so
    what is read is what was looked at; fd is None for others."""
    if not rel:
        fd = open_root(root)
        link = None
    else:
        pfd = open_parent(root, rel)
        try:
            name = rel[-1]
            st = os.stat(name, dir_fd=pfd, follow_symlinks=False)
            fd, link = None, None
            if stat.S_ISLNK(st.st_mode):
                link = os.readlink(name, dir_fd=pfd)
            elif stat.S_ISDIR(st.st_mode):
                fd = os.open(name, DIR_FLAGS, dir_fd=pfd)
            elif stat.S_ISREG(st.st_mode):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=pfd)
        finally:
            os.close(pfd)
    try:
        st = os.fstat(fd) if fd is not None else st
    except BaseException:
        os.close(fd)
        raise
    kind = kind_of(st.st_mode)
    if kind not in ('d', 'f') and fd is not None:
        os.close(fd)
        fd = None
    return Entry(list(parts), kind, stat.S_IMODE(st.st_mode), st.st_mtime, st.st_size, link,
                 (lambda: os.fdopen(os.dup(fd), 'rb')) if kind == 'f' else None), fd


def entry(host, parts):
    """An entry of the host's own files (copies into the container)."""
    st = os.lstat(host)
    kind = kind_of(st.st_mode)
    return Entry(list(parts), kind, stat.S_IMODE(st.st_mode), st.st_mtime, st.st_size,
                 os.readlink(host) if kind == 'l' else None, lambda: open(host, 'rb'))


class View:
    """A container's files as its processes see them: view is a rootfs or
    (upper, lower); binds are (host source, guest destination[, mode]).
    Lookups decide by path which area (bind, rootfs, layer) shows a name;
    every read and write then starts at that area's root FD."""

    def __init__(self, view, binds, readonly_root=False):
        self.view = view
        self.readonly_root = readonly_root
        self.binds = [(str(b[0]), '/' + b[1].strip('/'), b[2] if len(b) > 2 else 'rw') for b in binds]
        if isinstance(view, tuple):
            self.upper, self.lower = Path(view[0]), view[1]
            self.root = union.Root(*view)
        else:
            self.rootfs, self.root, self.upper = Path(view), None, None

    def resolve(self, path, follow=True):
        """Canonical parts of a guest path (symlinks resolved in the view)."""
        return runspec.guest_parts(self.view, [b[:2] for b in self.binds], path, follow)

    def bind(self, parts):
        """(source, parts under it, mode) of the bind holding parts, or None."""
        guest = '/' + '/'.join(parts)
        best = None
        for b in self.binds:
            dst = b[1]
            if guest == dst or dst == '/' or guest.startswith(dst + '/'):
                if best is None or len(dst) > len(best[1]):
                    best = b
        if not best:
            return None
        return Path(best[0]), [p for p in guest[len(best[1]):].split('/') if p], best[2]

    def anchor(self, parts, fill=False):
        """(area root, parts under it) of what the view shows at parts, or
        None; fill: a layer image's file is filled first."""
        b = self.bind(parts)
        if b:
            return b[0], b[1]
        if self.root is None:
            return self.rootfs, list(parts)
        host, layer = self.root.locate('/' + '/'.join(parts))
        if layer is None:
            return None
        if fill and layer:
            self.root.fill(host, layer)
        return self.root.layers[layer][0], list(parts)

    def open_entry(self, parts, top=()):
        """(Entry, fd) of canonical parts, or None when the view has none."""
        a = self.anchor(parts, fill=True)
        if a is None:
            return None
        try:
            return entry_at(a[0], a[1], top)
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as e:
            raise StoreError(f'/{"/".join(parts)} changed while copying: {e}') from None

    def stat(self, parts):
        got = self.open_entry(parts)
        if got is None:
            return None
        if got[1] is not None:
            os.close(got[1])
        return got[0]

    def exists(self, parts):
        return self.stat(parts) is not None

    def is_dir(self, parts):
        e = self.stat(parts)
        return e is not None and e.kind == 'd'

    def listdir(self, parts, fd):
        """Names in the directory at parts (fd: the one open_entry opened)."""
        if self.bind(parts) or self.root is None:
            names = set(os.listdir(fd))
        else:
            names = self.merged(parts)
        guest = '/' + '/'.join(parts)
        for b in self.binds:
            d = PurePosixPath(b[1])
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
            if image is not None:
                try:
                    self.root.expand(k, rel)
                except Exception:   # noqa: BLE001  (not a directory of that image)
                    continue
            try:
                e, fd = entry_at(layer, parts, ())
            except OSError:
                continue
            try:
                if e.kind == 'd':
                    names.update(n for n in os.listdir(fd) if not union.marker(n))
            finally:
                if fd is not None:
                    os.close(fd)
        return {n for n in names if self.root.locate('/' + '/'.join(parts + [n]))[1] is not None}

    def walk(self, parts, top):
        """Entries of the tree at canonical parts, named top/...; top empty:
        the directory's contents only."""
        got = self.open_entry(parts, top)
        if got is None:
            return
        e, fd = got
        try:
            if top:
                yield e
            names = self.listdir(parts, fd) if e.kind == 'd' else []
        finally:
            if fd is not None:
                os.close(fd)
        for name in names:
            yield from self.walk(parts + [name], top + [name])

    def write_area(self, parts):
        """(area root, parts under it, whether it is an upper) to write
        canonical parts into; a read-only bind or root refuses."""
        b = self.bind(parts)
        if b:
            if b[2] == 'ro':
                raise StoreError(f'/{"/".join(parts)} is on a read-only volume')
            return b[0], b[1], False
        if self.root is not None:
            return self.upper, list(parts), True
        if self.readonly_root:
            raise StoreError("the container's root filesystem is read-only")
        return self.rootfs, list(parts), False


class GuestSink:
    """Writes entries under the canonical guest directory base: each one
    goes to the area that shows its path (a bind inside the copy is
    written in its source, as the container sees it); a mount point itself
    is kept."""

    def __init__(self, view, base):
        self.view, self.base = view, list(base)
        self.sinks = {}
        self.made = set()   # directories known to be in the upper
        # (Each entry is checked where it lands: base only locates them, so
        # a read-only root's directory may hold a writable file bind.)

    def upper_dir(self, guest):
        """The guest directory made in the upper as a --cow directory is
        (lower modes, whiteouts removed, opaque over a deleted one), also
        when a tar has no entry for it."""
        key = tuple(guest)
        if key in self.made:
            return
        try:
            os.close(union.mkdirs_fd(self.view.upper, self.view.lower, '/' + '/'.join(guest)))
        except OSError as e:
            raise StoreError(f'/{"/".join(guest)}: {e}') from None
        self.made.add(key)

    def update_file(self, root, e, guest):
        """A file bind's mount point: its content is replaced through the
        source (opened, not replaced), the mount stays."""
        if e.kind != 'f':
            raise StoreError(f'cannot replace the mount point /{"/".join(guest)}')
        with e.open() as src:
            fd = os.open(root, os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)
            try:
                dest = os.fstat(fd)
                if not stat.S_ISREG(dest.st_mode):
                    raise StoreError(f'cannot replace the mount point /{"/".join(guest)}')
                try:
                    source = os.fstat(src.fileno())
                except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
                    source = None   # (a tar member)
                if source is not None and (source.st_dev, source.st_ino) == (dest.st_dev, dest.st_ino):
                    return   # the bind's own source: already this content
                os.ftruncate(fd, 0)
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    unpack.write_all(fd, chunk)
                os.utime(fd, (e.mtime, e.mtime))
            finally:
                os.close(fd)

    def sink(self, root, upper):
        key = str(root)
        if key not in self.sinks:
            self.sinks[key] = DirSink(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC), upper)
        return self.sinks[key]

    def put(self, e):
        guest = self.base + e.parts
        root, rel, upper = self.view.write_area(guest)
        if not rel:
            if e.kind == 'd':
                if not os.path.isdir(root):
                    raise StoreError(f'cannot replace the mount point /{"/".join(guest)}')
                return
            if os.path.isdir(root):
                raise StoreError(f'cannot replace the mount point /{"/".join(guest)}')
            return self.update_file(root, e, guest)
        if e.kind == 'h':   # its target was written in this copy, maybe in another area
            lroot, lrel, lupper = self.view.write_area(self.base + e.link)
            if not lrel:
                raise StoreError(f'hard link {"/".join(e.parts)} to a mount point')
            try:
                fd = self.sink(lroot, lupper).root.open_file(lrel)
            except OSError:
                raise StoreError(f'hard link {"/".join(e.parts)} to missing {"/".join(e.link)}') from None
            mode = stat.S_IMODE(os.fstat(fd).st_mode)
            e = e._replace(kind='f', mode=mode, open=lambda: os.fdopen(fd, 'rb'))
        if upper and len(guest) > 1:
            self.upper_dir(guest[:-1])
        self.sink(root, upper).put(e._replace(parts=rel))
        if upper and e.kind == 'd':
            self.made.add(tuple(guest))

    def finish(self):
        for s in self.sinks.values():
            s.finish()


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
        # The source is opened before anything at the destination goes: it
        # may be the very file being replaced (a volume copied onto itself).
        src = None
        if e.kind == 'h':
            try:
                src = os.fdopen(self.root.open_file(e.link), 'rb')
            except OSError:
                raise StoreError(f'hard link {"/".join(e.parts)} to missing {"/".join(e.link)}') from None
        elif e.kind == 'f':
            src = e.open()
        try:
            self.place(fd, name, e, src)
        finally:
            if src is not None:
                src.close()

    def place(self, fd, name, e, src):
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
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=fd)
            try:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    unpack.write_all(out, chunk)
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
