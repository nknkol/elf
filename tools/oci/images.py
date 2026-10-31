"""Images: pull, load, save, install into the store (verify + unpack)."""
import gzip
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

import registry
import store as store_mod
import unpack
from registry import RegistryError
from store import StoreError

DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json'
DOCKER_CONFIG = 'application/vnd.docker.container.image.v1+json'
DOCKER_LAYER = 'application/vnd.docker.image.rootfs.diff.tar.gzip'
OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
OCI_INDEX = 'application/vnd.oci.image.index.v1+json'
OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
OCI_LAYER_GZIP = 'application/vnd.oci.image.layer.v1.tar+gzip'
OCI_LAYER_ZSTD = 'application/vnd.oci.image.layer.v1.tar+zstd'
OCI_LAYER = 'application/vnd.oci.image.layer.v1.tar'


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return 'sha256:' + h.hexdigest()


def put_blob(st, data):
    digest = 'sha256:' + hashlib.sha256(data).hexdigest()
    path = st.blob(digest)
    if not path.exists():
        tmp = path.with_name(path.name + '.tmp')
        tmp.write_bytes(data)
        tmp.replace(path)
    return digest


def human_size(n):
    for unit in ('B', 'kB', 'MB', 'GB', 'TB'):
        if n < 1000 or unit == 'TB':
            return f'{n:.3g}{unit}' if unit != 'B' else f'{n}B'
        n /= 1000


def log(message):
    print(message, file=sys.stderr, flush=True)


def check_platform(config):
    arch, os_name = config.get('architecture'), config.get('os')
    if (arch, os_name) != ('arm64', 'linux'):
        raise StoreError(f'image platform {os_name}/{arch} is not linux/arm64')


def install(st, config_bytes, manifest, names=(), repo_digests=(), quiet=False):
    """Verifies every layer against the config's diff_ids and unpacks the
    image (once). Layers are blobs already in the store. Returns the id."""
    config_digest = put_blob(st, config_bytes)
    image_id = config_digest.split(':')[1]
    config = json.loads(config_bytes)
    check_platform(config)
    target = st.image_dir(image_id)
    if not (target / 'config.json').exists():
        diff_ids = config.get('rootfs', {}).get('diff_ids', [])
        layers = manifest.get('layers', [])
        if len(diff_ids) != len(layers):
            raise StoreError('config diff_ids and manifest layers differ in number')
        work = st.tmpdir('image')
        try:
            (work / 'rootfs').mkdir()
            extractor = unpack.Extractor(work / 'rootfs')
            try:
                for i, (layer, diff_id) in enumerate(zip(layers, diff_ids)):
                    blob = st.blob(layer['digest'])
                    if sha256_file(blob) != layer['digest']:
                        blob.unlink()
                        raise StoreError(f'layer {layer["digest"]} is corrupt; removed')
                    if not quiet:
                        log(f'{layer["digest"][7:19]}: Extracting')
                    actual = extractor.layer(blob)
                    if actual != diff_id:
                        raise StoreError(f'layer {i}: diff_id {actual} does not match the config {diff_id}')
            finally:
                extractor.close()
            store_mod.write_json(work / 'meta.json', extractor.meta)
            store_mod.write_json(work / 'manifest.json', manifest)
            store_mod.write_json(work / 'info.json', {
                'created': store_mod.now(), 'repo_digests': list(repo_digests),
                'size': store_mod.tree_size(work / 'rootfs'),
                'layer_digests': [layer['digest'] for layer in layers]})
            (work / 'config.json').write_bytes(config_bytes)
            with st.lock():
                if not (target / 'config.json').exists():
                    if target.exists():
                        store_mod.remove(target)
                    work.rename(target)
        finally:
            if work.exists():
                store_mod.remove(work)
    elif repo_digests:
        with st.lock():
            info = store_mod.read_json(target / 'info.json', {})
            info['repo_digests'] = sorted(set(info.get('repo_digests', [])) | set(repo_digests))
            store_mod.write_json(target / 'info.json', info)
    for name in names:
        st.set_ref(name, image_id)
    return image_id


def pull(st, text, mirror=None, quiet=False):
    ref = registry.Reference(text)
    client = registry.Client(ref, mirror=mirror)
    if not quiet:
        log(f'{ref.tag or ref.digest}: Pulling from {registry.short_name(ref.repository)}')
    body, media, digest = client.manifest(ref.digest or ref.tag)
    top_digest = digest
    if media in registry.INDEX_TYPES:
        entry = registry.choose_platform(json.loads(body))
        body, media, digest = client.manifest(entry['digest'])
    manifest = json.loads(body)
    if manifest.get('schemaVersion') != 2 or 'config' not in manifest:
        raise RegistryError(f'unsupported manifest type {media}')
    put_blob(st, body)
    config_path = st.blob(manifest['config']['digest'])
    if not config_path.exists():
        client.blob(manifest['config']['digest'], config_path)
    for layer in manifest['layers']:
        path = st.blob(layer['digest'])
        if path.exists():
            if not quiet:
                log(f'{layer["digest"][7:19]}: Already exists')
            continue
        size = layer.get('size', 0)
        shown = [0]

        def progress(have, digest=layer['digest'], size=size, shown=shown):
            if not quiet and sys.stderr.isatty() and have - shown[0] > (4 << 20):
                shown[0] = have
                print(f'\r{digest[7:19]}: Downloading {human_size(have)}/{human_size(size)}',
                      end='', file=sys.stderr, flush=True)
        client.blob(layer['digest'], path, progress)
        if not quiet:
            if sys.stderr.isatty() and shown[0]:
                print('\r', end='', file=sys.stderr)
            log(f'{layer["digest"][7:19]}: Pull complete')
    names = [ref.full] if ref.tag else []
    image_id = install(st, config_path.read_bytes(), manifest, names,
                       [f'{ref.repository}@{top_digest}'], quiet)
    if not quiet:
        log(f'Digest: {top_digest}')
        log(f'Status: Downloaded newer image for {registry.short_name(ref.repository)}'
            f':{ref.tag}' if ref.tag else f'Status: Downloaded {ref.full}')
    return image_id


# Archives: docker save (manifest.json) and OCI layout (index.json).
class Archive:
    """Members of a tar or a directory, read by name without extraction."""

    def __init__(self, path):
        self.path = Path(path)
        self.dir = self.path.is_dir()
        if not self.dir:
            self.tar = tarfile.open(self.path)
            self.members = {str(PurePosixPath(m.name.lstrip('./') or '.')): m
                            for m in self.tar.getmembers()}

    def read(self, name):
        name = str(PurePosixPath(name.lstrip('./')))
        if self.dir:
            unpack.clean_name(name)
            return (self.path / name).read_bytes()
        member = self.members.get(name)
        if member is None:
            raise StoreError(f'archive has no {name}')
        while member.issym() or member.islnk():
            linked = PurePosixPath(name).parent / member.linkname if member.issym() else PurePosixPath(member.linkname)
            name = os.path.normpath(str(linked))
            member = self.members.get(name)
            if member is None:
                raise StoreError(f'archive link to missing {name}')
        return self.tar.extractfile(member)

    def exists(self, name):
        name = str(PurePosixPath(name.lstrip('./')))
        return (self.path / name).exists() if self.dir else name in self.members

    def copy_blob(self, st, name):
        """Copies a member into the blob store; returns its digest."""
        src = self.read(name)
        if isinstance(src, bytes):
            src = io.BytesIO(src)
        tmp = st.home / 'tmp' / f'load-{os.getpid()}'
        h = hashlib.sha256()
        with open(tmp, 'wb') as out:
            for chunk in iter(lambda: src.read(1 << 20), b''):
                h.update(chunk)
                out.write(chunk)
        digest = 'sha256:' + h.hexdigest()
        tmp.replace(st.blob(digest))
        return digest

    def data(self, name):
        src = self.read(name)
        return src if isinstance(src, bytes) else src.read()


def layer_media(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
    if magic[:2] == b'\x1f\x8b':
        return OCI_LAYER_GZIP
    if magic == b'\x28\xb5\x2f\xfd':
        return OCI_LAYER_ZSTD
    return OCI_LAYER


def load(st, path, quiet=False):
    archive = Archive(path)
    loaded = []
    if archive.exists('index.json'):
        index = json.loads(archive.data('index.json'))
        for entry in index.get('manifests', []):
            names = []
            ref_name = entry.get('annotations', {}).get('io.containerd.image.name') or \
                entry.get('annotations', {}).get('org.opencontainers.image.ref.name')
            descriptor = entry
            body = archive.data('blobs/' + descriptor['digest'].replace(':', '/'))
            if descriptor.get('mediaType') in registry.INDEX_TYPES:
                descriptor = registry.choose_platform(json.loads(body))
                body = archive.data('blobs/' + descriptor['digest'].replace(':', '/'))
            manifest = json.loads(body)
            for layer in manifest['layers']:
                digest = archive.copy_blob(st, 'blobs/' + layer['digest'].replace(':', '/'))
                if digest != layer['digest']:
                    raise StoreError(f'archive blob {layer["digest"]} has digest {digest}')
            config = archive.data('blobs/' + manifest['config']['digest'].replace(':', '/'))
            if 'sha256:' + hashlib.sha256(config).hexdigest() != manifest['config']['digest']:
                raise StoreError('archive config digest mismatch')
            if ref_name and ':' in ref_name and '/' not in ref_name.split(':')[-1]:
                names.append(registry.Reference(ref_name).full)
            elif ref_name:
                pass   # A bare tag annotation (OCI layout): no repository name.
            put_blob(st, body)
            loaded.append((install(st, config, manifest, names, quiet=quiet), names))
        if loaded:
            return loaded
    if not archive.exists('manifest.json'):
        raise StoreError('not a docker-archive or OCI layout (no manifest.json / index.json)')
    for entry in json.loads(archive.data('manifest.json')):
        config = archive.data(entry['Config'])
        layers = []
        for name in entry['Layers']:
            digest = archive.copy_blob(st, name)
            blob = st.blob(digest)
            layers.append({'mediaType': layer_media(blob), 'digest': digest,
                           'size': blob.stat().st_size})
        manifest = {'schemaVersion': 2, 'mediaType': OCI_MANIFEST,
                    'config': {'mediaType': OCI_CONFIG, 'size': len(config),
                               'digest': 'sha256:' + hashlib.sha256(config).hexdigest()},
                    'layers': layers}
        put_blob(st, json.dumps(manifest).encode())
        names = [registry.Reference(t).full for t in entry.get('RepoTags') or []]
        loaded.append((install(st, config, manifest, names, quiet=quiet), names))
    return loaded


def save(st, image_ids_and_names, out):
    """docker-archive with an OCI index too (as Docker 25+ writes it)."""
    def add(tar, name, data):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mtime = 0
        tar.addfile(info, io.BytesIO(data))

    docker_manifest, oci_index, added = [], [], set()
    with tarfile.open(fileobj=out, mode='w|') as tar:
        add(tar, 'oci-layout', b'{"imageLayoutVersion":"1.0.0"}')
        for image_id, names in image_ids_and_names:
            info = st.image_info(image_id)
            manifest = info['manifest']
            config = (st.image_dir(image_id) / 'config.json').read_bytes()
            body = json.dumps(manifest, separators=(',', ':')).encode()
            for digest, data in ((manifest['config']['digest'], config),
                                 ('sha256:' + hashlib.sha256(body).hexdigest(), body)):
                if digest not in added:
                    added.add(digest)
                    add(tar, f'blobs/sha256/{digest[7:]}', data)
            for layer in manifest['layers']:
                if layer['digest'] in added:
                    continue
                added.add(layer['digest'])
                blob = st.blob(layer['digest'])
                if not blob.exists():
                    raise StoreError(f'layer blob {layer["digest"]} is missing; pull the image again')
                tar.add(str(blob), f'blobs/sha256/{layer["digest"][7:]}', recursive=False)
            docker_manifest.append({
                'Config': f'blobs/sha256/{image_id}',
                'RepoTags': [registry.short_name(n.rsplit(':', 1)[0]) + ':' + n.rsplit(':', 1)[1]
                             for n in names],
                'Layers': [f'blobs/sha256/{layer["digest"][7:]}' for layer in manifest['layers']]})
            for n in names or [None]:
                entry = {'mediaType': manifest.get('mediaType', OCI_MANIFEST),
                         'digest': 'sha256:' + hashlib.sha256(body).hexdigest(), 'size': len(body)}
                if n:
                    entry['annotations'] = {'io.containerd.image.name': n,
                                            'org.opencontainers.image.ref.name': n.rsplit(':', 1)[1]}
                oci_index.append(entry)
        add(tar, 'manifest.json', json.dumps(docker_manifest).encode())
        add(tar, 'index.json', json.dumps({'schemaVersion': 2, 'mediaType': OCI_INDEX,
                                           'manifests': oci_index}).encode())


def gzip_file(src, dest):
    """Compresses src to dest (deterministic header); returns the digest."""
    h = hashlib.sha256()

    class Tee(io.RawIOBase):
        def __init__(self, f):
            self.f = f

        def writable(self):
            return True

        def write(self, b):
            h.update(b)
            return self.f.write(b)

    with open(src, 'rb') as inp, open(dest, 'wb') as raw:
        with gzip.GzipFile(fileobj=Tee(raw), mode='wb', mtime=0, compresslevel=6) as z:
            shutil.copyfileobj(inp, z, 1 << 20)
    return 'sha256:' + h.hexdigest()
