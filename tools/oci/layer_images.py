"""Layer images in the store (docs/OCI.md, R6 "层镜像").

`docker image erofs IMAGE` turns each layer blob into layers/<diff_id>.erofs
(shared by every image with that layer; tools/oci/erofs.py) with its cache
layers/<diff_id>.cache, expanded on demand by the loader. A --cow container
of a converted image runs on those caches as its lowers instead of the
image's unpacked rootfs. The loader takes at most CONFIG_MAX_LOWERS lowers:
the bottom layers of a longer image are merged into one image of their
chain (layers/chain-<id>.erofs, whiteouts applied).

--prune drops the image's unpacked rootfs; what needs a full tree (a copy
container, build FROM, commit) unpacks it again from the blobs."""
import hashlib
import json
import os
from pathlib import Path

import erofs
import store as store_mod
import unpack
from store import StoreError

MAX_LOWERS = 8  # CONFIG_MAX_LOWERS (src/payload/include/config.h)


def layers_dir(st):
    d = st.home / 'layers'
    d.mkdir(exist_ok=True)
    return d


class Hashing:
    """A plain tar stream that hashes what is read (the layer's diff_id)."""

    def __init__(self, f):
        self.f, self.h = f, hashlib.sha256()

    def read(self, n=-1):
        data = self.f.read(n)
        self.h.update(data)
        return data

    def drain(self):
        while self.read(1 << 20):
            pass


def _build(out, sources, check_ids=None):
    """Writes the image out from layer blobs, bottom first; check_ids: the
    diff_ids the plain tars must have."""
    tmp = Path(str(out) + '.part')
    w = erofs.Writer(tmp)
    try:
        for i, blob in enumerate(sources):
            raw = unpack.open_layer(blob)
            try:
                f = Hashing(raw)
                w.add_tar(f, apply_whiteouts=len(sources) > 1)
                f.drain()
            finally:
                raw.close()
            if check_ids and 'sha256:' + f.h.hexdigest() != check_ids[i]:
                raise StoreError(f'layer {blob.name[:12]}: diff_id does not match the config')
        w.finish()
    finally:
        w.close()
    os.replace(tmp, out)


def stack_entries(st, image_id):
    """[(cache, image)] topmost first, from images/<id>/layers.json (None
    when the image is not converted or a layer image is missing)."""
    entries = store_mod.read_json(st.image_dir(image_id) / 'layers.json', [])
    if not entries or not all(Path(i).exists() for _, i in entries):
        return None
    return [(Path(c), Path(i)) for c, i in entries]


def convert(st, image_id, quiet=True):
    """Layer images of an image (made once per layer); records the stack."""
    info = st.image_info(image_id)
    diff_ids = info['config'].get('rootfs', {}).get('diff_ids', [])
    blobs = [st.blob(layer['digest']) for layer in info['manifest'].get('layers', [])]
    if len(blobs) != len(diff_ids) or not all(b.exists() for b in blobs):
        raise StoreError(f'{image_id[:12]}: layer blobs are missing; pull or load the image again')
    d = layers_dir(st)
    # Layers beyond the lower limit: the bottom ones as one image.
    split = max(0, len(diff_ids) - (MAX_LOWERS - 1)) if len(diff_ids) > MAX_LOWERS else 0
    groups = []
    if split:
        chain = hashlib.sha256('\n'.join(diff_ids[:split]).encode()).hexdigest()
        groups.append((f'chain-{chain}', blobs[:split], None))
    for blob, diff_id in list(zip(blobs, diff_ids))[split:]:
        groups.append((diff_id.split(':')[1], [blob], [diff_id]))
    entries = []
    for name, sources, ids in groups:
        image = d / f'{name}.erofs'
        cache = d / f'{name}.cache'
        if not image.exists():
            if not quiet:
                print(f'{name[:12]}: Converting', flush=True)
            _build(image, sources, ids)
        cache.mkdir(exist_ok=True)
        entries.append((cache, image))
    entries.reverse()  # topmost first
    with st.lock():
        store_mod.write_json(st.image_dir(image_id) / 'layers.json', [[str(c), str(i)] for c, i in entries])
    return entries


def rootfs(st, image_id):
    """The image's unpacked rootfs, unpacked again when it was pruned."""
    root = st.image_dir(image_id) / 'rootfs'
    if root.exists():
        return root
    info = st.image_info(image_id)
    work = st.tmpdir('unpack')
    try:
        (work / 'rootfs').mkdir()
        extractor = unpack.Extractor(work / 'rootfs')
        try:
            for layer in info['manifest'].get('layers', []):
                blob = st.blob(layer['digest'])
                if not blob.exists():
                    raise StoreError(f'{image_id[:12]}: layer blobs are missing; pull or load the image again')
                extractor.layer(blob)
        finally:
            extractor.close()
        with st.lock():
            if not root.exists():
                os.rename(work / 'rootfs', root)
            meta = st.image_dir(image_id) / 'info.json'
            data = store_mod.read_json(meta, {})
            data.pop('pruned', None)
            store_mod.write_json(meta, data)
    finally:
        store_mod.remove(work)
    return root


def prune_rootfs(st, image_id):
    """Drops the unpacked rootfs of a converted image. Containers that use
    it (copies made from it keep their own; read-only, in-place and --cow
    containers without layer images use it directly) keep it."""
    if stack_entries(st, image_id) is None:
        raise StoreError(f'{image_id[:12]}: convert the image first (docker image erofs)')
    for c in st.containers():
        h = c['HostConfig']
        if c['Image'] == image_id and (h.get('ReadonlyRootfs') or h.get('InPlace') or
                                       (h.get('Cow') and not h.get('LayerImages'))):
            raise StoreError(f'container {c["Id"][:12]} uses the unpacked rootfs of {image_id[:12]}')
    root = st.image_dir(image_id) / 'rootfs'
    if not root.exists():
        return 0
    freed = store_mod.tree_size(root)
    trash = st.home / 'tmp' / f'prune-{image_id}'
    with st.lock():
        os.rename(root, trash)
        meta = st.image_dir(image_id) / 'info.json'
        data = store_mod.read_json(meta, {})
        data['pruned'] = True
        store_mod.write_json(meta, data)
    store_mod.remove(trash)
    return freed


def collect(st):
    """Removes layer images (and caches) no image or container refers to.
    Returns the bytes freed."""
    d = st.home / 'layers'
    if not d.exists():
        return 0
    keep = set()
    for image_id in st.images():
        for _, image in json.loads((st.image_dir(image_id) / 'layers.json').read_text()) \
                if (st.image_dir(image_id) / 'layers.json').exists() else []:
            keep.add(Path(image).name[:-len('.erofs')])
    for c in st.containers():
        for _, image in c['HostConfig'].get('LayerImages') or []:
            keep.add(Path(image).name[:-len('.erofs')])
    freed = 0
    for p in list(d.iterdir()):
        name = p.name.rsplit('.', 1)[0]
        if name in keep:
            continue
        freed += store_mod.tree_size(p) if p.is_dir() else p.stat().st_size
        store_mod.remove(p)
    return freed
