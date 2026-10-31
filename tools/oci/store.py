"""Local storage (docs/OCI.md, "结构"): blobs, images, refs, containers, volumes.

Metadata changes hold an exclusive flock on <home>/lock. Directories that
are being created live under <home>/tmp and are renamed into place, so an
interrupted pull or create leaves no half-made image or container."""
import contextlib
import fcntl
import json
import os
import secrets
import shutil
import time
from pathlib import Path

import unpack

DEFAULT_HOME = '/data/storage/el2/base/files/elf-oci'


class StoreError(Exception):
    pass


def now():
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + 'Z'


def write_json(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(value, indent=2))
    tmp.replace(path)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        if default is not None:
            return default
        raise


def tree_size(path):
    total = 0
    for top, dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(top, name)).st_size
            except OSError:
                pass
    return total


def remove(path):
    """Removes a tree even with read-only directories in it."""
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return
    if path.is_dir() and not path.is_symlink():
        fd = os.open(path.parent, unpack.DIR_FLAGS)
        try:
            unpack.remove_tree(fd, path.name)
        finally:
            os.close(fd)
    else:
        path.unlink()


class Store:
    def __init__(self, home=None):
        self.home = Path(home or os.environ.get('ELF_OCI_HOME') or DEFAULT_HOME)
        for sub in ('blobs/sha256', 'images', 'containers', 'volumes', 'tmp', 'build-cache'):
            (self.home / sub).mkdir(parents=True, exist_ok=True)
        self._check_case()

    def _check_case(self):
        marker = self.home / '.case-check'
        if marker.exists():
            return
        probe = self.home / 'tmp' / 'CaseProbe'
        probe.touch()
        try:
            if (self.home / 'tmp' / 'caseprobe').exists():
                raise StoreError(f'{self.home} is case-insensitive; set ELF_OCI_HOME to a '
                                 'case-sensitive location such as /data/storage/el2/base/files/elf-oci')
        finally:
            probe.unlink()
        marker.touch()

    @contextlib.contextmanager
    def lock(self):
        with open(self.home / 'lock', 'a') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            yield

    def tmpdir(self, prefix):
        path = self.home / 'tmp' / f'{prefix}-{secrets.token_hex(6)}'
        path.mkdir()
        return path

    # Blobs.
    def blob(self, digest):
        algorithm, _, hexdigest = digest.partition(':')
        if algorithm != 'sha256' or len(hexdigest) != 64 or not all(c in '0123456789abcdef' for c in hexdigest):
            raise StoreError(f'bad digest {digest}')
        return self.home / 'blobs' / 'sha256' / hexdigest

    # References: canonical name:tag -> image id (the config digest hex).
    def refs(self):
        return read_json(self.home / 'refs.json', {})

    def set_ref(self, name, image_id):
        with self.lock():
            refs = self.refs()
            refs[name] = image_id
            write_json(self.home / 'refs.json', refs)

    def drop_ref(self, name):
        with self.lock():
            refs = self.refs()
            image_id = refs.pop(name, None)
            write_json(self.home / 'refs.json', refs)
            return image_id

    def image_dir(self, image_id):
        return self.home / 'images' / image_id

    def images(self):
        return sorted(p.name for p in (self.home / 'images').iterdir()
                      if (p / 'config.json').exists())

    def image_info(self, image_id):
        d = self.image_dir(image_id)
        return {'id': image_id, 'config': read_json(d / 'config.json'),
                'manifest': read_json(d / 'manifest.json', {}),
                'info': read_json(d / 'info.json', {})}

    def resolve_image(self, text):
        """An image id from a name[:tag], a full or short id, or sha256:id."""
        import registry
        refs = self.refs()
        candidates = []
        try:
            ref = registry.Reference(text)
            if ref.digest:
                for image_id in self.images():
                    if ref.digest in self.image_info(image_id)['info'].get('repo_digests', []) \
                            or ref.digest == 'sha256:' + image_id:
                        return image_id
            elif ref.full in refs:
                return refs[ref.full]
        except registry.RegistryError:
            pass
        short = text[7:] if text.startswith('sha256:') else text
        if len(short) >= 4 and all(c in '0123456789abcdef' for c in short):
            candidates = [i for i in self.images() if i.startswith(short)]
            if len(candidates) == 1:
                return candidates[0]
            if len(candidates) > 1:
                raise StoreError(f'ambiguous image id {text}')
        raise StoreError(f'No such image: {text}')

    def image_names(self, image_id):
        return sorted(name for name, i in self.refs().items() if i == image_id)

    # Containers.
    def container_dir(self, cid):
        return self.home / 'containers' / cid

    def containers(self):
        out = []
        for p in (self.home / 'containers').iterdir():
            if (p / 'run.json').exists():
                out.append(read_json(p / 'run.json'))
        return sorted(out, key=lambda c: c['Created'], reverse=True)

    def resolve_container(self, text):
        matches = [c for c in self.containers() if c['Name'] == text]
        if not matches and len(text) >= 1:
            matches = [c for c in self.containers() if c['Id'].startswith(text)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise StoreError(f'multiple containers match {text}')
        raise StoreError(f'No such container: {text}')

    def save_container(self, record):
        write_json(self.container_dir(record['Id']) / 'run.json', record)

    def load_container(self, cid):
        return read_json(self.container_dir(cid) / 'run.json')

    @staticmethod
    def new_id():
        return secrets.token_hex(32)

    # Volumes (R2).
    def volume_dir(self, name):
        return self.home / 'volumes' / name

    def volumes(self):
        return sorted(p.name for p in (self.home / 'volumes').iterdir() if (p / 'data').is_dir())

    def create_volume(self, name, labels=None):
        d = self.volume_dir(name)
        if not (d / 'data').is_dir():
            (d / 'data').mkdir(parents=True, exist_ok=True)
            write_json(d / 'volume.json', {'Name': name, 'CreatedAt': now(), 'Labels': labels or {}})
        return d / 'data'
