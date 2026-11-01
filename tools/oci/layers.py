"""Layer computation without overlayfs (docs/OCI.md, R3 "层计算").

A snapshot records every path's type, size, mtime, mode and link target;
two snapshots give the added, changed and deleted paths, which become a
layer tar (deletions as .wh. whiteouts). commit and diff compare a
container's copy with its image's rootfs the same way."""
import gzip
import hashlib
import os
import stat
import tarfile
from pathlib import Path

IGNORED = {'/.elf-exec', '/.elf-exec.tmp'}


def scan(root):
    """path -> (kind, size, mtime_ns, mode, link) for every entry under root."""
    out = {}
    root = str(root)

    def walk(host, guest):
        try:
            entries = list(os.scandir(host))
        except OSError:
            return
        for entry in entries:
            path = guest + '/' + entry.name
            if path in IGNORED:
                continue
            st = entry.stat(follow_symlinks=False)
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                out[path] = ('l', 0, st.st_mtime_ns, 0, os.readlink(entry.path))
            elif stat.S_ISDIR(mode):
                out[path] = ('d', 0, 0, stat.S_IMODE(mode), '')
                walk(entry.path, path)
            elif stat.S_ISREG(mode):
                out[path] = ('f', st.st_size, st.st_mtime_ns, stat.S_IMODE(mode), '')
            else:
                out[path] = ('o', 0, 0, 0, '')
    walk(root, '')
    return out


def changes(before, after):
    """(added or changed paths, deleted paths), parents before children."""
    changed = sorted(p for p, sig in after.items() if before.get(p) != sig)
    deleted = sorted(p for p in before if p not in after)
    # A deleted directory's children need no whiteouts of their own.
    top = []
    for p in deleted:
        if not top or not p.startswith(top[-1] + '/'):
            top.append(p)
    return changed, top


def owner_changes(before_meta, after_meta):
    """Paths whose recorded owner or mode differs between two meta.json
    states: changed for a layer although their content is not."""
    out = set()
    for key in ('owners', 'modes'):
        b, a = before_meta.get(key) or {}, after_meta.get(key) or {}
        out |= {p for p in set(b) | set(a) if b.get(p) != a.get(p)}
    return out


def kinds(before, after):
    """docker diff lines: A added, C changed, D deleted."""
    changed, deleted = changes(before, after)
    out = {}
    for p in changed:
        out[p] = 'C' if p in before else 'A'
    for p in deleted:
        out[p] = 'D'
    # Directories whose contents changed are changed themselves.
    for p in list(out):
        parent = os.path.dirname(p)
        while parent not in ('', '/') and parent not in out:
            out[parent] = 'C'
            parent = os.path.dirname(parent)
    return sorted(((k, p) for p, k in out.items()), key=lambda x: x[1])


def write_layer(root, changed, deleted, out_path, modes=None, owners=None):
    """Writes the plain layer tar; returns its diff_id. Parent directories
    of changed entries are included (as Docker does). modes and owners
    (meta.json, R5) give what the host does not hold; the rest is root's."""
    root = Path(root)
    modes = modes or {}
    owners = owners or {}
    entries = set(changed)
    for p in list(changed) + list(deleted):
        parent = os.path.dirname(p)
        while parent not in ('', '/'):
            entries.add(parent)
            parent = os.path.dirname(parent)
    h = hashlib.sha256()

    class Hashing:
        def __init__(self, f):
            self.f = f

        def write(self, b):
            h.update(b)
            return self.f.write(b)

    with open(out_path, 'wb') as raw:
        with tarfile.open(fileobj=Hashing(raw), mode='w|', format=tarfile.PAX_FORMAT) as tar:
            whiteouts = {os.path.dirname(p) + '/.wh.' + os.path.basename(p) for p in deleted}
            for p in sorted(entries | whiteouts):
                name = p.lstrip('/')
                if p in whiteouts:
                    info = tarfile.TarInfo(name)
                    info.mode = 0o644
                    tar.addfile(info)
                    continue
                host = root / name
                try:
                    info = tar.gettarinfo(str(host), name)
                except FileNotFoundError:
                    continue
                info.uid, info.gid = owners.get(p, (0, 0))
                info.uname = info.gname = ''
                if p in modes:
                    info.mode = modes[p]
                if info.isreg():
                    with open(host, 'rb') as f:
                        tar.addfile(info, f)
                elif info.isdir() or info.issym():
                    tar.addfile(info)
    return 'sha256:' + h.hexdigest()


def compress(st, plain_path):
    """gzip the plain tar into the blob store; returns (digest, size)."""
    tmp = Path(str(plain_path) + '.gz')
    h = hashlib.sha256()

    class Hashing:
        def __init__(self, f):
            self.f = f

        def write(self, b):
            h.update(b)
            return self.f.write(b)

        def flush(self):
            self.f.flush()

    with open(plain_path, 'rb') as inp, open(tmp, 'wb') as raw:
        with gzip.GzipFile(fileobj=Hashing(raw), mode='wb', mtime=0, compresslevel=6) as z:
            for chunk in iter(lambda: inp.read(1 << 20), b''):
                z.write(chunk)
    digest = 'sha256:' + h.hexdigest()
    size = tmp.stat().st_size
    tmp.replace(st.blob(digest))
    return digest, size
