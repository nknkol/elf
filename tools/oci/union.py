"""Copy-on-write containers (docs/OCI.md, R6), on the host side.

A container made with --cow runs on the image's rootfs as a read-only
lower layer with containers/<id>/upper as its writable upper layer (the
loader's --root UPPER --lower ROOTFS; src/payload/include/union_view.h).
The upper is an OCI layer diff: copied-up and new entries, ".wh.<name>"
whiteouts and ".wh..wh..opq" opaque markers. This module reads the merged
view the same way, for docker cp, diff, commit and user lookup.

The lower may instead be a Stack: layer images (erofs files, topmost
first), each expanded on demand into its cache directory (the loader's
--lower CACHE --lower-image IMAGE; tools/oci/erofs.py). Lookups here expand
the caches the same way the payload does."""
import os
import shutil
import stat
from pathlib import Path, PurePosixPath

import layers

OPAQUE = '.wh..wh..opq'


def marker(name):
    return name.startswith('.wh.')


class Stack:
    """Lower layers that are layer images: [(cache, image)], topmost first."""

    def __init__(self, entries):
        self.entries = [(Path(c), Path(i)) for c, i in entries]

    def __str__(self):
        return ':'.join(str(c) for c, _ in self.entries)

    def to_json(self):
        return [[str(c), str(i)] for c, i in self.entries]


def lowers(lower):
    """[(directory, image or None)] of a lower (a directory or a Stack)."""
    if isinstance(lower, Stack):
        return list(lower.entries)
    return [(Path(lower), None)]


def is_dir(path):
    return path.is_dir() and not path.is_symlink()


class Root:
    """The merged view of upper over the lowers; root(name) is the host path
    of a canonical guest path (relative, no symlinks followed) in the topmost
    layer that shows it, or the upper's path when none does. A regular file
    of a layer image is filled first."""

    def __init__(self, upper, lower):
        self.upper, self.lower = Path(upper), lower
        self.layers = [(self.upper, None)] + lowers(lower)
        self.expanded = set()

    def __call__(self, name):
        host, layer = self.locate('/' + str(name).lstrip('/'))
        if layer:
            self.fill(host, layer)
        return host

    def expand(self, layer, rel):
        """The directory rel of an image layer's cache, expanded."""
        cache, image = self.layers[layer]
        if image is not None and (layer, rel) not in self.expanded:
            import erofs
            erofs.expand(image, cache, rel)
            self.expanded.add((layer, rel))

    def fill(self, host, layer):
        cache, image = self.layers[layer]
        if image is not None and os.path.isfile(host) and not os.path.islink(host):
            import erofs
            erofs.fill(image, cache, str(Path(host).relative_to(cache)))

    def locate(self, guest):
        """(host path, layer: 0 upper, k a lower, None missing)."""
        parts = [p for p in PurePosixPath(guest).parts if p != '/']
        n = len(self.layers)
        alive = [True] * n
        for k in range(1, n):
            self.expand(k, '')
        for i, name in enumerate(parts):
            last = i == len(parts) - 1
            if marker(name):
                return self.upper.joinpath(*parts), None
            first, first_dir = None, False
            next_alive = [False] * n
            for k in range(n):
                if not alive[k]:
                    continue
                p = self.layers[k][0].joinpath(*parts[:i + 1])
                if os.path.lexists(p):
                    d = is_dir(p)
                    if first is None:
                        first, first_dir = k, d
                    if first_dir and d:
                        self.expand(k, '/'.join(parts[:i + 1]))
                        next_alive[k] = True
                        if os.path.lexists(p / OPAQUE):
                            break
                    else:
                        break
                elif os.path.lexists(p.parent / ('.wh.' + name)):
                    break
            if first is None:
                return self.upper.joinpath(*parts), None
            host = self.layers[first][0].joinpath(*parts[:i + 1])
            if last:
                return host, first
            if not first_dir:
                return self.layers[first][0].joinpath(*parts), first  # ENOTDIR
            alive = next_alive
        return self.upper, 0


def lower_scan(lower):
    """layers.scan of a lower: a directory, or a Stack merged from its images
    (read from the images, nothing expanded)."""
    if not isinstance(lower, Stack):
        return layers.scan(lower)
    import erofs
    out = {}
    for _, image in reversed(lower.entries):
        with erofs.Image(image) as img:
            overlay(out, image_entries(img, img.inode(img.root)), '')
    return out


def image_entries(img, ino):
    """Directory entries of an image in the shape overlay() reads."""
    for name, nid in img.entries(ino):
        if name in (b'.', b'..'):
            continue
        child = img.inode(nid)
        kind = stat.S_IFMT(child.mode)
        mtime = child.mtime * 10**9 + child.nsec
        sub = None
        if kind == stat.S_IFDIR:
            sig = ('d', 0, 0, child.mode & 0o7777, '')
            sub = (lambda child=child: image_entries(img, child))
        elif kind == stat.S_IFLNK:
            sig = ('l', 0, mtime, 0, os.fsdecode(img.read(child)))
        elif kind == stat.S_IFREG:
            sig = ('f', child.size, mtime, child.mode & 0o7777, '')
        else:
            sig = ('o', 0, 0, 0, '')
        yield os.fsdecode(name), sig, sub


def dir_entries(host):
    """Directory entries of a host directory in the shape overlay() reads."""
    try:
        entries = sorted(os.scandir(host), key=lambda e: e.name)
    except OSError:
        return
    for entry in entries:
        st = entry.stat(follow_symlinks=False)
        mode = st.st_mode
        if stat.S_ISLNK(mode):
            yield entry.name, ('l', 0, st.st_mtime_ns, 0, os.readlink(entry.path)), None
        elif stat.S_ISDIR(mode):
            yield entry.name, ('d', 0, 0, stat.S_IMODE(mode), ''), (lambda p=entry.path: dir_entries(p))
        elif stat.S_ISREG(mode):
            yield entry.name, ('f', st.st_size, st.st_mtime_ns, stat.S_IMODE(mode), ''), None
        else:
            yield entry.name, ('o', 0, 0, 0, ''), None


def overlay(out, entries, guest):
    """Applies one layer (its entries, as an OCI diff) onto a scan."""
    def drop(prefix):
        for p in [p for p in out if p == prefix or p.startswith(prefix + '/')]:
            del out[p]
    entries = list(entries)
    if any(name == OPAQUE for name, _, _ in entries):
        for p in [p for p in out if p.startswith(guest + '/')]:
            del out[p]
    for name, sig, sub in entries:
        if marker(name):
            if name != OPAQUE and not name.startswith('.wh..'):
                drop(guest + '/' + name[4:])
            continue
        path = guest + '/' + name
        if path in layers.IGNORED:
            continue
        if sig[0] != 'd':
            drop(path)
            out[path] = sig
            continue
        if out.get(path, ('d',))[0] != 'd':
            drop(path)
        out[path] = sig
        overlay(out, sub(), path)


def scan(upper, lower):
    """layers.scan of the merged view."""
    out = lower_scan(lower)
    overlay(out, dir_entries(str(upper)), '')
    return out


def guest_view(upper, lower, db):
    """owners.guest_view of the merged view (records keyed by the inodes of
    every layer; the topmost copy wins). Caches of layer images are walked
    as far as they are expanded (a file with a record was looked up)."""
    import owners
    root = Root(upper, lower)
    view = {}
    for k in range(len(root.layers) - 1, -1, -1):
        for p, v in owners.guest_view(root.layers[k][0], db).items():
            if not any(marker(part) for part in p.split('/')) and root.locate(p)[1] == k:
                view[p] = v
    return view


def from_meta(upper, lower, meta, db):
    """owners.from_meta for a --cow container: the records of meta.json's
    paths, by the inode of the layer that shows each (expanding caches on
    the way). Returns {(dev, ino): path}."""
    import owners
    if not isinstance(lower, Stack):
        return owners.from_meta(lower, meta, db)
    root = Root(upper, lower)
    records, paths = {}, {}
    for key in set(meta.get('owners', {})) | set(meta.get('modes', {})):
        host, layer = root.locate(key)
        if not layer:
            continue
        try:
            st = os.lstat(host)
        except OSError:
            continue
        uid, gid = meta.get('owners', {}).get(key, (0, 0))
        mode = None if stat.S_ISLNK(st.st_mode) else meta.get('modes', {}).get(key)
        records[(st.st_dev, st.st_ino)] = (uid, gid, mode)
        paths[(st.st_dev, st.st_ino)] = key
    owners.create(db, records)
    return paths


def mkdirs(upper, lower, guest):
    """Makes the guest directory in the upper, parents included (modes of
    the lower's directories kept); whiteouts on the way removed."""
    root = Root(upper, lower)
    parts = [p for p in PurePosixPath(guest).parts if p != '/']
    for i in range(1, len(parts) + 1):
        sub = '/' + '/'.join(parts[:i])
        host, layer = root.locate(sub)
        target = Path(upper).joinpath(*parts[:i])
        if layer == 0:
            continue
        if layer:
            if not host.is_dir() or host.is_symlink():
                raise NotADirectoryError(sub)
            target.mkdir()
            target.chmod(stat.S_IMODE(host.stat().st_mode) | 0o700)
            continue
        whiteout = target.parent / ('.wh.' + target.name)
        target.mkdir()
        if os.path.lexists(whiteout):
            whiteout.unlink()
            (target / OPAQUE).touch()
    return Path(upper).joinpath(*parts)


def writable(upper, lower, host):
    """For docker cp into the container: the upper's path for a host path
    the merged view resolved (a lower directory is made in the upper)."""
    host = Path(host)
    for layer, _ in lowers(lower):
        try:
            rel = host.relative_to(layer)
        except ValueError:
            continue
        return mkdirs(upper, lower, '/' + str(rel)) if host.is_dir() else Path(upper) / rel
    return host


def apply(upper, dest):
    """Applies the upper onto dest, a full copy of the lower (commit)."""
    upper, dest = Path(upper), Path(dest)

    def remove(path):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif os.path.lexists(path):
            path.unlink()

    def walk(src, out):
        names = sorted(os.listdir(src))
        if OPAQUE in names and out.is_dir():
            for child in os.listdir(out):
                remove(out / child)
        for name in names:
            s, d = src / name, out / name
            if marker(name):
                if name != OPAQUE and not name.startswith('.wh..'):
                    remove(out / name[4:])
                continue
            if str(s.relative_to(upper)) in ('.elf-exec', '.elf-exec.tmp'):
                continue
            if s.is_dir() and not s.is_symlink():
                if os.path.lexists(d) and (not d.is_dir() or d.is_symlink()):
                    remove(d)
                d.mkdir(exist_ok=True)
                shutil.copystat(s, d, follow_symlinks=False)
                walk(s, d)
                continue
            remove(d)
            if s.is_symlink():
                os.symlink(os.readlink(s), d)
            else:
                shutil.copy2(s, d)
    walk(upper, dest)


def diff_entries(upper):
    """The layer an upper holds, for build (R6: RUN writes the upper, so no
    scan): (changed paths, deleted paths, opaque directories), guest paths."""
    changed, deleted, opaque = [], [], []

    def walk(host, guest):
        names = sorted(os.listdir(host))
        if OPAQUE in names:
            opaque.append(guest or '/')
        for name in names:
            path = guest + '/' + name
            if marker(name):
                if not name.startswith('.wh..'):
                    deleted.append(guest + '/' + name[4:])
                continue
            if path in layers.IGNORED:
                continue
            changed.append(path)
            if is_dir(Path(host, name)):
                walk(os.path.join(host, name), path)
    walk(str(upper), '')
    return changed, deleted, opaque


def merge(upper, dest):
    """Moves the upper into dest, the lower it ran on (build): renames on the
    same file system, so nothing is copied; markers are applied and dropped.
    The upper is consumed."""
    upper, dest = Path(upper), Path(dest)

    def remove(path):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        elif os.path.lexists(path):
            path.unlink()

    def strip(top):
        for dirpath, dirnames, filenames in os.walk(top):
            for name in filenames + dirnames:
                if marker(name):
                    remove(Path(dirpath, name))
            dirnames[:] = [d for d in dirnames if not marker(d)]

    def walk(src, out):
        names = sorted(os.listdir(src))
        if OPAQUE in names:
            for child in os.listdir(out):
                remove(out / child)
        for name in names:
            s, d = src / name, out / name
            if marker(name):
                if name != OPAQUE and not name.startswith('.wh..'):
                    remove(out / name[4:])
                continue
            if is_dir(s) and is_dir(d) and not (s / OPAQUE).exists():
                walk(s, d)
                shutil.copystat(s, d, follow_symlinks=False)
                continue
            remove(d)
            os.rename(s, d)
            if is_dir(d):
                strip(d)
    walk(upper, dest)
    shutil.rmtree(upper, ignore_errors=True)


def owner_view(upper, lower, db, known):
    """guest_view after a build RUN without walking the lower: records of
    lower files are named by known ({(dev, ino): path}, from owners.from_meta)
    and the rest must be in the upper; a record of neither (a lower file
    without a meta.json entry chowned in place) falls back to the full walk."""
    import owners
    records = owners.read(db)
    if not records:
        return {}
    view, seen = {}, set()
    for dirpath, dirnames, filenames in os.walk(str(upper)):
        dirnames[:] = [d for d in dirnames if not marker(d)]
        guest = '/' + os.path.relpath(dirpath, str(upper)).lstrip('.').lstrip('/')
        for name in dirnames + [f for f in filenames if not marker(f)]:
            st = os.lstat(os.path.join(dirpath, name))
            key = (st.st_dev, st.st_ino)
            seen.add(key)
            r = records.get(key)
            if r:
                view[guest.rstrip('/') + '/' + name] = (r[0] or 0, r[1] or 0, r[2])
    root = Root(upper, lower)
    for key, r in records.items():
        if key in seen:
            continue
        p = known.get(key)
        if p is None:
            return guest_view(upper, lower, db)
        if root.locate(p)[1] == 1:
            view[p] = (r[0] or 0, r[1] or 0, r[2])
    return view
