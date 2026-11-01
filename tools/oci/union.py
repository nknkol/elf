"""Copy-on-write containers (docs/OCI.md, R6), on the host side.

A container made with --cow runs on the image's rootfs as a read-only
lower layer with containers/<id>/upper as its writable upper layer (the
loader's --root UPPER --lower ROOTFS; src/payload/include/union_view.h).
The upper is an OCI layer diff: copied-up and new entries, ".wh.<name>"
whiteouts and ".wh..wh..opq" opaque markers. This module reads the merged
view the same way, for docker cp, diff, commit and user lookup."""
import os
import shutil
import stat
from pathlib import Path, PurePosixPath

import layers

OPAQUE = '.wh..wh..opq'


def marker(name):
    return name.startswith('.wh.')


class Root:
    """The merged view of upper over lower; root(name) is the host path of a
    canonical guest path (relative, no symlinks followed) in the topmost
    layer that shows it, or the upper's path when none does."""

    def __init__(self, upper, lower):
        self.upper, self.lower = Path(upper), Path(lower)

    def __call__(self, name):
        return self.locate('/' + str(name).lstrip('/'))[0]

    def locate(self, guest):
        """(host path, layer: 0 upper, 1 lower, None missing)."""
        parts = [p for p in PurePosixPath(guest).parts if p != '/']
        u, l = self.upper, self.lower
        u_alive = l_alive = True
        for i, name in enumerate(parts):
            last = i == len(parts) - 1
            if marker(name):
                return self.upper.joinpath(*parts), None
            in_u = u_alive and os.path.lexists(u / name)
            if u_alive and not in_u and os.path.lexists(u / ('.wh.' + name)):
                l_alive = False
            in_l = l_alive and os.path.lexists(l / name)
            if in_u:
                if last:
                    return u / name, 0
                if not is_dir(u / name):
                    return self.upper.joinpath(*parts), 0  # ENOTDIR
                l_alive = in_l and is_dir(l / name) and not os.path.lexists(u / name / OPAQUE)
            elif in_l:
                if last:
                    return l / name, 1
                if not is_dir(l / name):
                    return self.lower.joinpath(*parts), 1  # ENOTDIR
                u_alive = False
            else:
                return self.upper.joinpath(*parts), None
            u, l = u / name, l / name
        return self.upper, 0


def is_dir(path):
    return path.is_dir() and not path.is_symlink()


def scan(upper, lower):
    """layers.scan of the merged view."""
    out = layers.scan(lower)
    root = str(upper)

    def drop(prefix):
        for p in [p for p in out if p == prefix or p.startswith(prefix + '/')]:
            del out[p]

    def walk(host, guest):
        try:
            entries = sorted(os.scandir(host), key=lambda e: e.name)
        except OSError:
            return
        if any(e.name == OPAQUE for e in entries):
            for p in [p for p in out if p.startswith(guest + '/')]:
                del out[p]
        for entry in entries:
            if marker(entry.name):
                if entry.name != OPAQUE and not entry.name.startswith('.wh..'):
                    drop(guest + '/' + entry.name[4:])
                continue
            path = guest + '/' + entry.name
            if path in layers.IGNORED:
                continue
            st = entry.stat(follow_symlinks=False)
            mode = st.st_mode
            if not stat.S_ISDIR(mode):
                drop(path)
            if stat.S_ISLNK(mode):
                out[path] = ('l', 0, st.st_mtime_ns, 0, os.readlink(entry.path))
            elif stat.S_ISDIR(mode):
                if out.get(path, ('d',))[0] != 'd':
                    drop(path)
                out[path] = ('d', 0, 0, stat.S_IMODE(mode), '')
                walk(entry.path, path)
            elif stat.S_ISREG(mode):
                out[path] = ('f', st.st_size, st.st_mtime_ns, stat.S_IMODE(mode), '')
            else:
                out[path] = ('o', 0, 0, 0, '')
    walk(root, '')
    return out


def guest_view(upper, lower, db):
    """owners.guest_view of the merged view (records keyed by the inodes of
    both layers; the upper's copy wins)."""
    import owners
    merged = scan(upper, lower)
    view = {p: v for p, v in owners.guest_view(lower, db).items() if p in merged}
    view.update(owners.guest_view(upper, db))
    return {p: v for p, v in view.items() if p in merged}


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
        if layer == 1:
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
    for layer in (Path(lower),):
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
