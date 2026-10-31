"""Registry v2 client: references, bearer tokens, manifests, blobs.

Only HTTPS (plain HTTP for localhost registries used by tests), schema 2 /
OCI manifests. Every blob is verified against its digest while it streams."""
import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DOCKER_HUB = 'docker.io'
HUB_API = 'registry-1.docker.io'
MANIFEST_TYPES = [
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
    'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json',
]
INDEX_TYPES = MANIFEST_TYPES[:2]
USER_AGENT = 'elf-oci/1'


class RegistryError(Exception):
    pass


class Reference:
    """[registry/]name[:tag][@digest] with Docker's defaults."""

    _NAME = re.compile(r'^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$')

    def __init__(self, text):
        self.text = text
        rest, _, digest = text.partition('@')
        tag = None
        slash = rest.rfind('/')
        colon = rest.rfind(':')
        if colon > slash:
            rest, tag = rest[:colon], rest[colon + 1:]
        first, _, remainder = rest.partition('/')
        if remainder and ('.' in first or ':' in first or first == 'localhost'):
            registry, name = first, remainder
        else:
            registry, name = DOCKER_HUB, rest
        if registry in ('index.docker.io', 'registry-1.docker.io'):
            registry = DOCKER_HUB
        if registry == DOCKER_HUB and '/' not in name:
            name = 'library/' + name
        if not self._NAME.match(name):
            raise RegistryError(f'invalid reference format: {text}')
        if tag is not None and not re.match(r'^[\w][\w.-]{0,127}$', tag):
            raise RegistryError(f'invalid tag in reference: {text}')
        if digest and not re.match(r'^sha256:[0-9a-f]{64}$', digest):
            raise RegistryError(f'invalid digest in reference: {text}')
        self.registry, self.name = registry, name
        self.tag = tag if tag is not None or digest else 'latest'
        self.digest = digest or None

    @property
    def repository(self):
        return f'{self.registry}/{self.name}'

    @property
    def full(self):
        """Canonical name: docker.io/library/alpine:latest."""
        if self.tag:
            return f'{self.repository}:{self.tag}'
        return f'{self.repository}@{self.digest}'

    @property
    def api(self):
        return HUB_API if self.registry == DOCKER_HUB else self.registry


def short_name(repository):
    """Docker's display form: alpine, user/app, ghcr.io/x/y."""
    for prefix in ('docker.io/library/', 'docker.io/'):
        if repository.startswith(prefix):
            return repository[len(prefix):]
    return repository


def credentials(registry):
    """user, password from ~/.docker/config.json (DOCKER_CONFIG respected)."""
    path = Path(os.environ.get('DOCKER_CONFIG', Path.home() / '.docker')) / 'config.json'
    try:
        auths = json.loads(path.read_text()).get('auths', {})
    except (OSError, ValueError):
        return None
    keys = [registry, f'https://{registry}']
    if registry == DOCKER_HUB:
        keys += ['https://index.docker.io/v1/', 'index.docker.io']
    for key in keys:
        entry = auths.get(key)
        if entry and entry.get('auth'):
            user, _, password = base64.b64decode(entry['auth']).decode().partition(':')
            return user, password
    return None


def store_credentials(registry, user, password):
    """`login`: writes the auth entry of ~/.docker/config.json (mode 0600)."""
    path = Path(os.environ.get('DOCKER_CONFIG', Path.home() / '.docker')) / 'config.json'
    try:
        config = json.loads(path.read_text())
    except (OSError, ValueError):
        config = {}
    key = 'https://index.docker.io/v1/' if registry == DOCKER_HUB else registry
    auth = base64.b64encode(f'{user}:{password}'.encode()).decode()
    config.setdefault('auths', {})[key] = {'auth': auth}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(config, f, indent=2)
    tmp.replace(path)


def remove_credentials(registry):
    path = Path(os.environ.get('DOCKER_CONFIG', Path.home() / '.docker')) / 'config.json'
    try:
        config = json.loads(path.read_text())
    except (OSError, ValueError):
        return False
    key = 'https://index.docker.io/v1/' if registry == DOCKER_HUB else registry
    found = config.get('auths', {}).pop(key, None) is not None
    path.write_text(json.dumps(config, indent=2))
    return found


class Client:
    def __init__(self, ref, mirror=None, auth=None, push=False):
        self.ref = ref
        self.base = self._base(mirror if mirror and ref.registry == DOCKER_HUB else ref.api)
        self.auth = auth if auth is not None else credentials(ref.registry)
        self.scope = f'repository:{ref.name}:pull' + (',push' if push else '')
        self.token = None

    @staticmethod
    def _base(host):
        if '://' in host:
            return host.rstrip('/')
        local = host.split(':')[0] in ('localhost', '127.0.0.1')
        return ('http://' if local else 'https://') + host

    def _authorize(self, challenge):
        scheme, _, params = challenge.partition(' ')
        if scheme.lower() == 'basic':
            if not self.auth:
                raise RegistryError('authentication required')
            self.token = 'Basic ' + base64.b64encode(':'.join(self.auth).encode()).decode()
            return
        fields = dict(re.findall(r'(\w+)="([^"]*)"', params))
        realm = fields.get('realm')
        if not realm:
            raise RegistryError(f'unsupported auth challenge: {challenge}')
        query = {'service': fields.get('service', ''), 'scope': self.scope}
        request = urllib.request.Request(realm + '?' + urllib.parse.urlencode(query),
                                         headers={'User-Agent': USER_AGENT})
        if self.auth:
            request.add_header('Authorization', 'Basic ' +
                               base64.b64encode(':'.join(self.auth).encode()).decode())
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                answer = json.load(response)
        except urllib.error.HTTPError as e:
            raise RegistryError(f'token request failed: HTTP {e.code}') from None
        self.token = 'Bearer ' + (answer.get('token') or answer.get('access_token'))

    def request(self, method, path, headers=None, data=None, ok=(200,), full_url=None):
        url = full_url or f'{self.base}/v2/{path}'
        for attempt in range(2):
            request = urllib.request.Request(url, data=data, method=method,
                                             headers={'User-Agent': USER_AGENT, **(headers or {})})
            if self.token:
                request.add_header('Authorization', self.token)
            try:
                response = urllib.request.urlopen(request, timeout=120)
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0 and 'WWW-Authenticate' in e.headers:
                    self._authorize(e.headers['WWW-Authenticate'])
                    continue
                if e.code in ok:
                    return e
                detail = e.read(4096).decode(errors='replace')
                raise RegistryError(f'{method} {url}: HTTP {e.code} {detail.strip()[:300]}') from None
            except urllib.error.URLError as e:
                raise RegistryError(f'{method} {url}: {e.reason}') from None
            if response.status not in ok:
                raise RegistryError(f'{method} {url}: HTTP {response.status}')
            return response
        raise RegistryError(f'{method} {url}: unauthorized')

    def manifest(self, reference):
        """(bytes, media type, digest) of a manifest or an index."""
        with self.request('GET', f'{self.ref.name}/manifests/{reference}',
                          {'Accept': ', '.join(MANIFEST_TYPES)}) as response:
            body = response.read()
            media = response.headers.get('Content-Type', '').split(';')[0]
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        if reference.startswith('sha256:') and digest != reference:
            raise RegistryError(f'manifest digest mismatch: {digest} != {reference}')
        if not media or media == 'application/json':
            media = json.loads(body).get('mediaType', '')
        return body, media, digest

    def blob(self, digest, dest, progress=None, expected_size=None):
        """Downloads a blob to dest, resuming a partial dest.part; verifies it."""
        part = Path(str(dest) + '.part')
        have = part.stat().st_size if part.exists() else 0
        hasher = hashlib.sha256()
        if have:
            with part.open('rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    hasher.update(chunk)
        headers = {'Range': f'bytes={have}-'} if have else {}
        response = self.request('GET', f'{self.ref.name}/blobs/{digest}', headers, ok=(200, 206, 416))
        with response:
            if response.status == 200 and have:
                have, hasher = 0, hashlib.sha256()   # Range ignored: start over.
            mode = 'ab' if have else 'wb'
            if response.status != 416:
                with part.open(mode) as out:
                    for chunk in iter(lambda: response.read(1 << 20), b''):
                        hasher.update(chunk)
                        out.write(chunk)
                        have += len(chunk)
                        if progress:
                            progress(have)
        actual = 'sha256:' + hasher.hexdigest()
        if actual != digest:
            part.unlink(missing_ok=True)
            raise RegistryError(f'blob {digest}: content digest {actual} does not match')
        part.replace(dest)

    # Push (R3).
    def has_blob(self, digest):
        response = self.request('HEAD', f'{self.ref.name}/blobs/{digest}', ok=(200, 404))
        with response:
            return response.status == 200

    def upload_blob(self, digest, path):
        if self.has_blob(digest):
            return False
        response = self.request('POST', f'{self.ref.name}/blobs/uploads/', ok=(202,), data=b'')
        with response:
            location = response.headers['Location']
        url = urllib.parse.urljoin(self.base + '/', location)
        url += ('&' if '?' in url else '?') + urllib.parse.urlencode({'digest': digest})
        size = Path(path).stat().st_size
        with open(path, 'rb') as f:
            response = self.request('PUT', None, {'Content-Type': 'application/octet-stream',
                                                  'Content-Length': str(size)},
                                    data=f, ok=(201, 204), full_url=url)
        response.close()
        return True

    def put_manifest(self, reference, body, media):
        response = self.request('PUT', f'{self.ref.name}/manifests/{reference}',
                                {'Content-Type': media}, data=body, ok=(201, 202))
        response.close()

    def ping(self):
        """`login`: checks credentials against /v2/."""
        self.scope = ''
        response = self.request('GET', '', ok=(200,))
        response.close()


def choose_platform(index, arch='arm64', os_name='linux'):
    """The manifest descriptor for linux/arm64 (variant empty or v8)."""
    available = []
    for entry in index.get('manifests', []):
        platform = entry.get('platform', {})
        available.append('/'.join(filter(None, (platform.get('os'), platform.get('architecture'),
                                                platform.get('variant')))))
        if (platform.get('os') == os_name and platform.get('architecture') == arch
                and platform.get('variant') in (None, '', 'v8')):
            return entry
    raise RegistryError(f'no matching manifest for {os_name}/{arch} in the manifest list; '
                        f'available: {", ".join(a for a in available if a and "unknown" not in a)}')
