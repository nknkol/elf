"""The owner database of a container (docs/OCI.md, R5).

Owners and modes the host cannot hold (the app owns every file, and may
refuse setuid bits), keyed by (st_dev, st_ino) of the host file. The
payload maps the same file (src/payload/include/container_state.h): stat
reports what it records, chown/chmod and file creation keep it current.
Here it is created from an image's meta.json and read back into guest
paths for build, commit and diff."""
import os
import stat
import struct
from pathlib import Path

MAGIC = b'ELFOWN1\0'
HEADER = struct.Struct('<8sIIII40x')    # magic, capacity, count, lock, version
RECORD = struct.Struct('<QQIIII')       # dev, ino, uid, gid, mode, flags
USED, IDS, MODE, DEAD = 1, 2, 4, 8
MASK = (1 << 64) - 1
MIN_CAPACITY = 1 << 16


def owner_hash(dev, ino):
    h = ((ino * 0x9E3779B97F4A7C15) & MASK) ^ ((dev * 0xC2B2AE3D27D4EB4F) & MASK)
    return h ^ (h >> 29)


def capacity_for(count):
    cap = MIN_CAPACITY
    while cap < count * 4:
        cap <<= 1
    return cap


def create(path, records, capacity=None):
    """records: {(dev, ino): (uid, gid, mode or None)}. Written whole, then
    renamed into place (no container may be using the old file)."""
    capacity = capacity or capacity_for(len(records))
    slots = [None] * capacity
    for (dev, ino), (uid, gid, mode) in records.items():
        flags = USED | (IDS if uid or gid else 0) | (MODE if mode is not None else 0)
        if flags == USED:
            continue
        at = owner_hash(dev, ino) & (capacity - 1)
        while slots[at] is not None:
            at = (at + 1) & (capacity - 1)
        slots[at] = RECORD.pack(dev, ino, uid, gid, (mode or 0) & 0o7777, flags)
    used = sum(s is not None for s in slots)
    empty = RECORD.pack(0, 0, 0, 0, 0, 0)
    tmp = Path(str(path) + '.tmp')
    with open(tmp, 'wb') as f:
        f.write(HEADER.pack(MAGIC, capacity, used, 0, 0))
        f.write(b''.join(s or empty for s in slots))
    os.replace(tmp, path)


def read(path):
    """{(dev, ino): (uid or None, gid or None, mode or None)} of live records."""
    data = Path(path).read_bytes()
    magic, capacity, _count, _lock, _version = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ValueError(f'not an owner database: {path}')
    out = {}
    for i in range(capacity):
        dev, ino, uid, gid, mode, flags = RECORD.unpack_from(data, HEADER.size + i * RECORD.size)
        if not flags or flags & DEAD:
            continue
        out[(dev, ino)] = (uid if flags & IDS else None, gid if flags & IDS else None,
                           mode if flags & MODE else None)
    return out


def from_meta(rootfs, meta, path):
    """The database of a container's rootfs copy from its image's meta.json
    (owners and modes the unpacking recorded). Returns {(dev, ino): path}
    of the recorded files."""
    rootfs = str(rootfs)
    records, paths = {}, {}
    keys = set(meta.get('owners', {})) | set(meta.get('modes', {}))
    for key in keys:
        try:
            st = os.lstat(rootfs + key)
        except OSError:
            continue
        uid, gid = meta.get('owners', {}).get(key, (0, 0))
        mode = meta.get('modes', {}).get(key)
        if stat.S_ISLNK(st.st_mode):
            mode = None
        records[(st.st_dev, st.st_ino)] = (uid, gid, mode)
        paths[(st.st_dev, st.st_ino)] = key
    create(path, records)
    return paths


def guest_view(rootfs, path):
    """{guest path: (uid, gid, mode)} for every recorded file under rootfs."""
    records = read(path)
    if not records:
        return {}
    out = {}
    root = str(rootfs)

    def walk(host, guest):
        try:
            entries = list(os.scandir(host))
        except OSError:
            return
        for entry in entries:
            p = guest + '/' + entry.name
            st = entry.stat(follow_symlinks=False)
            r = records.get((st.st_dev, st.st_ino))
            if r:
                uid, gid, mode = r
                out[p] = (uid or 0, gid or 0, mode)
            if stat.S_ISDIR(st.st_mode):
                walk(entry.path, p)
    walk(root, '')
    return out


def update_meta(meta, view, paths=None):
    """meta['owners'] and meta['modes'] for paths (all when None) as view
    (guest_view) reports them; the meta of a new layer or image."""
    owners, modes = meta.setdefault('owners', {}), meta.setdefault('modes', {})
    for p in list(paths if paths is not None else set(owners) | set(modes) | set(view)):
        uid, gid, mode = view.get(p, (0, 0, None))
        if uid or gid:
            owners[p] = [uid, gid]
        else:
            owners.pop(p, None)
        if mode is not None:
            modes[p] = mode
        else:
            modes.pop(p, None)
    return meta
