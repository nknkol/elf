"""Layer images (docs/OCI.md, R6 "层镜像"): erofs files and their caches.

A layer is stored as an uncompressed erofs image (4 KiB blocks, extended
inodes, flat plain and flat inline data). Whiteouts stay ".wh." files and
opaque markers ".wh..wh..opq", as in an upper directory, so a layer image
is an OCI layer diff that the union view (src/payload/include/union_view.h)
can use as a lower. Owners, modes, setuid bits, device numbers and hard
links (one inode, several names) are in the image's own metadata.

The loader (--lower CACHE --lower-image IMAGE) expands such an image on
demand into its cache directory (src/payload/include/lazy_layer.h holds
the protocol); ensure() here does the same for the host side (docker cp,
diff, commit, owners). Images that mkfs.erofs makes without compression are
readable too; compressed or chunked files are refused."""
import fcntl
import os
import stat
import struct
import tarfile
from pathlib import Path, PurePosixPath

MAGIC = 0xE0F5E1E2
SB_OFFSET = 1024
BLKBITS = 12
BLKSZ = 1 << BLKBITS
FLAT_PLAIN, FLAT_INLINE = 0, 2
INODE = 64                       # extended inodes only
MAX_INLINE = BLKSZ - INODE       # a tail shares the inode's block
MARKER = '.wh..elf-lazy'
TMP = '.wh..elf-lazy-tmp'
OWN_PREFIX = '.wh..elf-'
ATIME_SEC, ATIME_NSEC = 15000000000, 123456789
FT = {stat.S_IFREG: 1, stat.S_IFDIR: 2, stat.S_IFCHR: 3, stat.S_IFBLK: 4, stat.S_IFIFO: 5,
      stat.S_IFSOCK: 6, stat.S_IFLNK: 7}


class ImageError(Exception):
    pass


# ------------------------------------------------------------------ model
class Node:
    __slots__ = ('mode', 'uid', 'gid', 'mtime', 'nsec', 'size', 'blkaddr', 'tail', 'target', 'rdev',
                 'children', 'nid', 'ino', 'nlink', 'dirdata')

    def __init__(self, mode, uid=0, gid=0, mtime=0, nsec=0):
        self.mode, self.uid, self.gid, self.mtime, self.nsec = mode, uid, gid, mtime, nsec
        self.size, self.blkaddr, self.tail, self.target, self.rdev = 0, 0, b'', b'', 0
        self.children = {} if stat.S_ISDIR(mode) else None
        self.nid = self.ino = None
        self.nlink = 1
        self.dirdata = None

    @property
    def is_dir(self):
        return self.children is not None


class Writer:
    """Builds one image: regular file data goes to the data area as it is
    added (a tar is read once, as a stream); finish() lays out directories
    and inodes after it."""

    def __init__(self, path):
        self.path = Path(path)
        self.tmp = Path(str(path) + '.tmp')
        self.f = open(self.tmp, 'w+b')
        self.f.write(b'\0' * BLKSZ)    # block 0: the superblock at 1024
        self.next_block = 1
        self.root = Node(stat.S_IFDIR | 0o755)

    def close(self):
        if self.f:
            self.f.close()
            self.f = None
        self.tmp.unlink(missing_ok=True)

    # --- tree
    def node(self, parts, create_dirs=True):
        cur = self.root
        for name in parts[:-1]:
            nxt = cur.children.get(name)
            if nxt is None or not nxt.is_dir:
                nxt = Node(stat.S_IFDIR | 0o755)
                cur.children[name] = nxt
            cur = nxt
        return cur

    def put(self, parts, node):
        if not parts:
            # The root itself: its attributes, its children kept.
            self.root.mode, self.root.uid, self.root.gid = node.mode, node.uid, node.gid
            self.root.mtime, self.root.nsec = node.mtime, node.nsec
            return self.root
        parent = self.node(parts)
        old = parent.children.get(parts[-1])
        if node.is_dir and old is not None and old.is_dir:
            node.children = old.children   # a directory entry again: contents stay
        parent.children[parts[-1]] = node
        return node

    def write_data(self, node, chunks):
        """Writes a regular file's content (an iterable of bytes); full
        blocks to the data area, the tail inline when it fits."""
        size = 0
        pending = b''
        start = self.next_block
        self.f.seek(start * BLKSZ)
        for chunk in chunks:
            pending += chunk
            size += len(chunk)
            full = len(pending) // BLKSZ * BLKSZ
            if full:
                self.f.write(pending[:full])
                pending = pending[full:]
        blocks = (size // BLKSZ)
        node.size = size
        node.blkaddr = start if blocks else 0
        self.next_block = start + blocks
        if pending and len(pending) > MAX_INLINE:
            # Too long to share the inode's block: one more (padded) block.
            self.f.write(pending + b'\0' * (BLKSZ - len(pending)))
            if not blocks:
                node.blkaddr = start
            self.next_block += 1
            node.tail = None          # flat plain
        else:
            node.tail = pending

    # --- inputs
    def add_tar(self, fileobj, apply_whiteouts=False):
        """A layer tar (plain stream): later entries replace earlier ones.
        apply_whiteouts (several layers merged into one image): ".wh." names
        remove what the layers before had, an opaque marker their contents
        of its directory; otherwise they are kept as files (an OCI diff)."""
        fresh = set()   # (directory, name) this tar made
        with tarfile.open(fileobj=fileobj, mode='r|') as tar:
            for m in tar:
                parts = clean_name(m.name)
                if parts:
                    fresh.add((id(self.node(parts)), parts[-1]))
                if apply_whiteouts and parts and parts[-1].startswith('.wh.'):
                    parent = self.node(parts)
                    if parts[-1] == '.wh..wh..opq':
                        for name in [n for n in parent.children if (id(parent), n) not in fresh]:
                            del parent.children[name]
                    else:
                        parent.children.pop(parts[-1][4:], None)
                    continue
                attrs = dict(uid=m.uid, gid=m.gid, mtime=int(m.mtime))
                perm = m.mode & 0o7777
                if m.isdir():
                    self.put(parts, Node(stat.S_IFDIR | perm, **attrs))
                elif m.isreg():
                    node = Node(stat.S_IFREG | perm, **attrs)
                    f = tar.extractfile(m)
                    self.write_data(node, iter(lambda: f.read(1 << 20), b''))
                    self.put(parts, node)
                elif m.issym():
                    node = Node(stat.S_IFLNK | 0o777, **attrs)
                    node.target = m.linkname.encode()
                    self.put(parts, node)
                elif m.islnk():
                    # A later hard link resolves against the tree as it is then.
                    self._link(parts, clean_name(m.linkname))
                elif m.ischr() or m.isblk() or m.isfifo():
                    kind = stat.S_IFCHR if m.ischr() else stat.S_IFBLK if m.isblk() else stat.S_IFIFO
                    node = Node(kind | perm, **attrs)
                    node.rdev = encode_dev(m.devmajor, m.devminor)
                    self.put(parts, node)

    def _link(self, parts, target):
        cur = self.root
        for name in target:
            cur = cur.children.get(name) if cur.is_dir else None
            if cur is None:
                return
        if cur.is_dir:
            return
        self.put(parts, cur)

    def add_dir(self, root, meta=None):
        """A directory tree (an unpacked rootfs); meta.json's owners and
        modes give what the host files do not hold."""
        meta = meta or {}
        owners, modes = meta.get('owners') or {}, meta.get('modes') or {}
        seen = {}

        def attrs(guest, st, kind):
            uid, gid = owners.get(guest, (0, 0))
            perm = modes.get(guest, stat.S_IMODE(st.st_mode))
            return Node(kind | (perm & 0o7777), uid, gid, st.st_mtime_ns // 10**9, st.st_mtime_ns % 10**9)

        def walk(host, guest, parts):
            for entry in sorted(os.scandir(host), key=lambda e: e.name):
                g = guest + '/' + entry.name
                p = parts + (entry.name,)
                st = entry.stat(follow_symlinks=False)
                if g in ('/.elf-exec', '/.elf-exec.tmp'):
                    continue
                if stat.S_ISDIR(st.st_mode):
                    self.put(p, attrs(g, st, stat.S_IFDIR))
                    walk(entry.path, g, p)
                elif stat.S_ISLNK(st.st_mode):
                    node = attrs(g, st, stat.S_IFLNK)
                    node.mode = stat.S_IFLNK | 0o777
                    node.target = os.fsencode(os.readlink(entry.path))
                    self.put(p, node)
                elif stat.S_ISREG(st.st_mode):
                    key = (st.st_dev, st.st_ino)
                    if st.st_nlink > 1 and key in seen:
                        self.put(p, seen[key])
                        continue
                    node = attrs(g, st, stat.S_IFREG)
                    with open(entry.path, 'rb') as f:
                        self.write_data(node, iter(lambda: f.read(1 << 20), b''))
                    self.put(p, node)
                    seen[key] = node
                elif stat.S_ISFIFO(st.st_mode):
                    self.put(p, attrs(g, st, stat.S_IFIFO))
        st = os.stat(root)
        self.root.mode = stat.S_IFDIR | modes.get('/', stat.S_IMODE(st.st_mode))
        self.root.mtime, self.root.nsec = st.st_mtime_ns // 10**9, st.st_mtime_ns % 10**9
        walk(str(root), '', ())

    # --- layout
    def finish(self, build_time=0):
        nodes, order = [], []
        # Breadth first, the root first (its nid must fit 16 bits).
        queue, ids = [(self.root, self.root)], {}
        while queue:
            node, parent = queue.pop(0)
            if id(node) in ids:
                ids[id(node)].nlink += 1
                continue
            ids[id(node)] = node
            node.nlink = 1
            order.append((node, parent))
            if node.is_dir:
                for name in sorted(node.children, key=os.fsencode):
                    queue.append((node.children[name], node))
        for node, _ in order:
            if node.is_dir:
                node.nlink = 2 + sum(1 for c in node.children.values() if c.is_dir)
        # Directory data: sizes depend on names only.
        for node, parent in order:
            if not node.is_dir:
                continue
            names = [b'.', b'..'] + [os.fsencode(n) for n in node.children]
            names.sort()
            blocks, cur, used = [], [], 0
            for name in names:
                if len(name) > 255:
                    raise ImageError(f'name too long: {name[:40]!r}')
                need = 12 + len(name)
                if cur and used + need > BLKSZ:
                    blocks.append(cur)
                    cur, used = [], 0
                cur.append(name)
                used += need
            blocks.append(cur)
            sizes = [12 * len(b) + sum(len(n) for n in b) for b in blocks]
            node.dirdata = (blocks, parent)
            node.size = BLKSZ * (len(blocks) - 1) + sizes[-1]
            full = len(blocks) - 1
            if sizes[-1] > MAX_INLINE:
                full += 1
            node.blkaddr = self.next_block if full else 0
            node.tail = b'' if sizes[-1] <= MAX_INLINE else None
            self.next_block += full
        for node, _ in order:
            if stat.S_ISLNK(node.mode):
                node.size = len(node.target)
                if node.size > MAX_INLINE:
                    node.blkaddr = self.next_block
                    self.f.seek(self.next_block * BLKSZ)
                    self.f.write(node.target + b'\0' * (BLKSZ - node.size))
                    self.next_block += 1
                    node.tail = None
                else:
                    node.tail = node.target
        # Inodes: 32-byte slots, a tail never crossing its block.
        meta_blk = self.next_block
        cur = 0
        for i, (node, _) in enumerate(order):
            if node.is_dir:  # (the inline block is written below)
                tail_len = node.size % BLKSZ if node.tail is not None else 0
            else:
                tail_len = len(node.tail or b'')
            off = (cur + 31) & ~31
            if tail_len and (off % BLKSZ) + INODE + tail_len > BLKSZ:
                off = (off + BLKSZ - 1) & ~(BLKSZ - 1)
            node.nid = off // 32
            node.ino = i + 1
            cur = off + INODE + tail_len
        if order[0][0].nid != 0:
            raise ImageError('root inode not first')
        # Directory blocks now that nids are known.
        for node, _ in order:
            if not node.is_dir:
                continue
            blocks, parent = node.dirdata
            for k, names in enumerate(blocks):
                data = self.dir_block(node, parent, names)
                last = k == len(blocks) - 1
                if last and node.tail is not None:
                    node.tail = data
                else:
                    self.f.seek((node.blkaddr + k) * BLKSZ)
                    self.f.write(data + b'\0' * (BLKSZ - len(data)))
        meta = bytearray(cur)
        for node, _ in order:
            meta[node.nid * 32:node.nid * 32 + INODE] = self.inode(node)
            tail = node.tail or b''
            if node.tail is not None and tail:
                at = node.nid * 32 + INODE
                meta[at:at + len(tail)] = tail
        self.f.seek(meta_blk * BLKSZ)
        self.f.write(bytes(meta))
        total = meta_blk + (len(meta) + BLKSZ - 1) // BLKSZ
        self.f.truncate(total * BLKSZ)
        sb = struct.pack('<IIIBBHQQIIII16s16sIHHHBBIQB23x', MAGIC, 0, 0, BLKBITS, 0, 0, len(order),
                         build_time, 0, total, meta_blk, 0, b'\0' * 16, b'\0' * 16, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        self.f.seek(SB_OFFSET)
        self.f.write(sb)
        self.f.close()
        self.f = None
        os.replace(self.tmp, self.path)

    @staticmethod
    def dir_block(node, parent, names):
        entries, blob = [], b''
        nameoff = 12 * len(names)
        for name in names:
            child = node if name == b'.' else parent if name == b'..' else node.children[os.fsdecode(name)]
            entries.append(struct.pack('<QHBB', child.nid, nameoff + len(blob), FT.get(stat.S_IFMT(child.mode), 0), 0))
            blob += name
        return b''.join(entries) + blob

    @staticmethod
    def inode(node):
        kind = stat.S_IFMT(node.mode)
        if kind in (stat.S_IFCHR, stat.S_IFBLK):
            layout, u, size = FLAT_PLAIN, node.rdev, 0
        elif node.size == 0:
            layout, u, size = FLAT_PLAIN, 0, 0
        elif not node.tail:
            layout, u, size = FLAT_PLAIN, node.blkaddr, node.size
        else:
            layout, u, size = FLAT_INLINE, node.blkaddr, node.size
        return struct.pack('<HHHHQIIIIQII16x', 1 | layout << 1, 0, node.mode, 0, size, u, node.ino,
                           node.uid, node.gid, node.mtime, node.nsec, node.nlink)


def encode_dev(major, minor):
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12)


def clean_name(name):
    path = PurePosixPath(name)
    if path.is_absolute():
        raise ImageError(f'absolute path in layer: {name}')
    parts = tuple(p for p in path.parts if p not in ('.', ''))
    if '..' in parts:
        raise ImageError(f'path with .. in layer: {name}')
    return parts


def from_layer(layer_path, out, build_time=0):
    """An image of one layer blob (gzip, zstd or plain tar)."""
    import unpack
    w = Writer(out)
    try:
        f = unpack.open_layer(layer_path)
        try:
            w.add_tar(f)
        finally:
            f.close()
        w.finish(build_time)
    finally:
        w.close()


def from_dir(root, out, meta=None, build_time=0):
    """An image of a directory tree (meta.json owners and modes applied)."""
    w = Writer(out)
    try:
        w.add_dir(root, meta)
        w.finish(build_time)
    finally:
        w.close()


# ------------------------------------------------------------------ reader
class Inode:
    __slots__ = ('nid', 'mode', 'layout', 'size', 'u', 'uid', 'gid', 'mtime', 'nsec', 'nlink', 'inline')


class Image:
    def __init__(self, path):
        self.f = open(path, 'rb')
        self.f.seek(0, 2)
        self.size = self.f.tell()
        sb = self.pread(SB_OFFSET, 128)
        if struct.unpack_from('<I', sb)[0] != MAGIC:
            raise ImageError(f'not an erofs image: {path}')
        self.blkbits = sb[12]
        if not 9 <= self.blkbits <= 12:
            raise ImageError('unsupported block size')
        self.blksz = 1 << self.blkbits
        self.root = struct.unpack_from('<H', sb, 14)[0]
        self.build_time, self.build_nsec = struct.unpack_from('<QI', sb, 24)
        self.meta = struct.unpack_from('<I', sb, 40)[0] << self.blkbits

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def pread(self, off, n):
        if off < 0 or off + n > self.size:
            raise ImageError('read past the image')
        self.f.seek(off)
        data = self.f.read(n)
        if len(data) != n:
            raise ImageError('short read')
        return data

    def inode(self, nid):
        off = self.meta + nid * 32
        b = self.pread(off, 32)
        fmt, xcount, mode = struct.unpack_from('<HHH', b)
        i = Inode()
        i.nid, i.mode, i.layout = nid, mode, (fmt >> 1) & 7
        if fmt & 1:
            b = self.pread(off, 64)
            (i.size, i.u, _ino, i.uid, i.gid, i.mtime, i.nsec, i.nlink) = struct.unpack_from('<QIIIIQII', b, 8)
            isize = 64
        else:
            i.nlink = struct.unpack_from('<H', b, 6)[0]
            i.size, = struct.unpack_from('<I', b, 8)
            i.u, = struct.unpack_from('<I', b, 16)
            i.uid, i.gid = struct.unpack_from('<HH', b, 24)
            i.mtime, i.nsec = self.build_time, self.build_nsec
            isize = 32
        i.inline = off + isize + (12 + (xcount - 1) * 4 if xcount else 0)
        kind = stat.S_IFMT(mode)
        if kind in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK) and i.size and i.layout not in (FLAT_PLAIN, FLAT_INLINE):
            raise ImageError(f'inode {nid}: compressed or chunked data is not supported')
        return i

    def read(self, ino, pos=0, n=None):
        n = ino.size - pos if n is None else n
        if pos < 0 or pos + n > ino.size:
            raise ImageError('read past the file')
        blocks_end = (ino.size >> self.blkbits) << self.blkbits if ino.layout == FLAT_INLINE else ino.size
        out = []
        while n:
            if pos < blocks_end:
                k = min(n, blocks_end - pos)
                out.append(self.pread((ino.u << self.blkbits) + pos, k))
            else:
                k = n
                out.append(self.pread(ino.inline + pos - blocks_end, k))
            pos += k
            n -= k
        return b''.join(out)

    def entries(self, ino):
        """[(name bytes, nid)] of a directory, '.' and '..' included."""
        out = []
        for start in range(0, ino.size, self.blksz):
            used = min(self.blksz, ino.size - start)
            b = self.read(ino, start, used)
            first = struct.unpack_from('<H', b, 8)[0]
            if first % 12 or first < 12 or first > used:
                raise ImageError('bad directory block')
            count = first // 12
            for k in range(count):
                nid, off = struct.unpack_from('<QH', b, 12 * k)
                end = struct.unpack_from('<H', b, 12 * (k + 1) + 8)[0] if k + 1 < count else used
                name = b[off:end]
                if k + 1 == count:
                    name = name.rstrip(b'\0')
                if not name or end <= off:
                    raise ImageError('bad directory entry')
                out.append((name, nid))
        return out

    def lookup(self, rel):
        ino = self.inode(self.root)
        for part in [p for p in str(rel).split('/') if p]:
            if not stat.S_ISDIR(ino.mode):
                raise NotADirectoryError(rel)
            name = os.fsencode(part)
            for n, nid in self.entries(ino):
                if n == name:
                    ino = self.inode(nid)
                    break
            else:
                raise FileNotFoundError(rel)
        return ino

    def walk(self, ino=None, prefix=''):
        """(guest path, Inode) of every entry below ino (the root)."""
        ino = ino or self.inode(self.root)
        for name, nid in self.entries(ino):
            if name in (b'.', b'..'):
                continue
            child = self.inode(nid)
            path = prefix + '/' + os.fsdecode(name)
            yield path, child
            if stat.S_ISDIR(child.mode):
                yield from self.walk(child, path)


# ------------------------------------------------------------------ cache
def placeholder(st):
    return stat.S_ISREG(st.st_mode) and int(st.st_atime) == ATIME_SEC and st.st_atime_ns % 10**9 == ATIME_NSEC


def _cache_dir(cache, parts):
    fd = os.open(cache, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in parts:
            if name in ('.', '..') or '/' in name:
                raise ValueError(name)
            nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd


def _exists(name, dir_fd):
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _times(ino, placeholder_mark=False):
    m = ino.mtime * 10**9 + ino.nsec
    return ((ATIME_SEC * 10**9 + ATIME_NSEC) if placeholder_mark else m, m)


def expand(image, cache, rel=''):
    """Expands the directory rel of the cache (lazy_expand)."""
    parts = [p for p in str(rel).split('/') if p]
    with Image(image) as img:
        ino = img.lookup('/'.join(parts))
        if not stat.S_ISDIR(ino.mode):
            raise NotADirectoryError(rel)
        fd = _cache_dir(cache, parts)
        try:
            if _exists(MARKER, fd):
                return
            fcntl.flock(fd, fcntl.LOCK_EX)
            if _exists(MARKER, fd):
                return
            for remove in (lambda: os.unlink(TMP, dir_fd=fd), lambda: os.rmdir(TMP, dir_fd=fd)):
                try:
                    remove()
                    break
                except OSError:
                    pass
            for name, nid in img.entries(ino):
                if name in (b'.', b'..') or b'/' in name or b'\0' in name:
                    continue
                child = os.fsdecode(name)
                if child.startswith(OWN_PREFIX) or _exists(child, fd):
                    continue
                c = img.inode(nid)
                kind, perm = stat.S_IFMT(c.mode), c.mode & 0o7777
                if kind == stat.S_IFDIR:
                    os.mkdir(TMP, 0o700, dir_fd=fd)
                    os.chmod(TMP, perm | 0o700, dir_fd=fd)
                elif kind == stat.S_IFLNK:
                    os.symlink(img.read(c), TMP, dir_fd=fd)
                elif kind == stat.S_IFIFO:
                    # No content to complete, so made at its own name (some
                    # storage, HarmonyOS app storage, refuses to rename one).
                    # (HarmonyOS refuses any later change of a FIFO: the
                    # mode is then the image's under the umask.)
                    try:
                        os.mkfifo(child, perm & 0o777, dir_fd=fd)
                    except OSError:
                        continue   # storage that refuses FIFOs: skipped
                    try:
                        os.chmod(child, perm, dir_fd=fd)
                        os.utime(child, ns=_times(c), dir_fd=fd, follow_symlinks=False)
                    except OSError:
                        pass
                    continue
                elif kind == stat.S_IFREG:
                    f = os.open(TMP, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
                    try:
                        if c.size:
                            os.ftruncate(f, c.size)
                        try:
                            os.fchmod(f, perm)
                        except PermissionError:
                            os.fchmod(f, perm & ~0o6000)
                        os.utime(f, ns=_times(c, bool(c.size)))
                        if c.size and not placeholder(os.fstat(f)):
                            raise OSError('the cache file system does not keep the placeholder mark')
                    finally:
                        os.close(f)
                    os.rename(TMP, child, src_dir_fd=fd, dst_dir_fd=fd)
                    continue
                else:
                    continue
                try:  # (HarmonyOS refuses times of symlinks)
                    os.utime(TMP, ns=_times(c), dir_fd=fd, follow_symlinks=False)
                except OSError:
                    pass
                os.rename(TMP, child, src_dir_fd=fd, dst_dir_fd=fd)
            os.close(os.open(MARKER, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=fd))
            if parts:
                os.utime(fd, ns=_times(ino))
        finally:
            os.close(fd)


def fill(image, cache, rel):
    """Fills the placeholder at rel in place (lazy_fill)."""
    parts = [p for p in str(rel).split('/') if p]
    dfd = _cache_dir(cache, parts[:-1])
    try:
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        except OSError:
            return
        try:
            if not placeholder(os.fstat(fd)):
                return
            fcntl.flock(fd, fcntl.LOCK_EX)
            st = os.fstat(fd)
            if not placeholder(st):
                return
            with Image(image) as img:
                ino = img.lookup('/'.join(parts))
                if not stat.S_ISREG(ino.mode) or ino.size != st.st_size:
                    raise ImageError(f'{rel}: the cache does not match the image')
                mode = stat.S_IMODE(st.st_mode)
                if not mode & 0o200:
                    os.fchmod(fd, mode | 0o200)
                out = os.open(parts[-1], os.O_WRONLY | os.O_NOFOLLOW, dir_fd=dfd)
                try:
                    for pos in range(0, ino.size, 1 << 20):
                        data = img.read(ino, pos, min(1 << 20, ino.size - pos))
                        os.pwrite(out, data, pos)
                finally:
                    os.close(out)
                try:
                    os.fchmod(fd, ino.mode & 0o7777)
                except PermissionError:
                    os.fchmod(fd, ino.mode & 0o7777 & ~0o6000)
                os.utime(fd, ns=_times(ino))
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


def ensure(image, cache, rel='', fill_file=False):
    """Every directory on the way to rel expanded (rel too when it is one);
    fill_file: a regular file at rel filled. Returns the host path."""
    parts = [p for p in str(rel).split('/') if p]
    expand(image, cache, '')
    host = Path(cache)
    for i, name in enumerate(parts):
        host = host / name
        try:
            st = os.lstat(host)
        except OSError:
            return Path(cache).joinpath(*parts)
        if stat.S_ISDIR(st.st_mode):
            expand(image, cache, '/'.join(parts[:i + 1]))
        elif i == len(parts) - 1 and fill_file and stat.S_ISREG(st.st_mode):
            fill(image, cache, '/'.join(parts))
        else:
            return Path(cache).joinpath(*parts)
    return host


def materialize(image, cache):
    """The whole image expanded and filled (for tools that read every file)."""
    expand(image, cache, '')
    stack = ['']
    while stack:
        rel = stack.pop()
        expand(image, cache, rel)
        for entry in os.scandir(os.path.join(cache, rel.lstrip('/')) if rel else cache):
            if entry.name.startswith('.wh..elf-'):
                continue
            sub = rel + '/' + entry.name
            st = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                stack.append(sub)
            elif placeholder(st):
                fill(image, cache, sub)
