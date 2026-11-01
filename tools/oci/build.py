"""docker build, commit, diff, push (docs/OCI.md, R3).

Each stage works in its own copy of the base rootfs. RUN executes under
elfloader in that copy; every instruction that may change files is
bracketed by two snapshots, and the difference is the instruction's layer.
The cache key of an instruction is its parent's key, the instruction text
after substitution and the content hash of COPY/ADD sources; a hit applies
the cached layer instead of running the instruction."""
import argparse
import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path, PurePosixPath

import images
import layers
import owners as owners_mod
import registry
import runspec
import runtime
import store as store_mod
import unpack
from store import StoreError

FS_INSTRUCTIONS = {'RUN', 'COPY', 'ADD', 'WORKDIR'}
DEFAULT_SHELL = ['/bin/sh', '-c']
PLATFORM_ARGS = {'TARGETPLATFORM': 'linux/arm64', 'TARGETOS': 'linux', 'TARGETARCH': 'arm64',
                 'TARGETVARIANT': '', 'BUILDPLATFORM': 'linux/arm64', 'BUILDOS': 'linux',
                 'BUILDARCH': 'arm64', 'BUILDVARIANT': ''}
PROXY_ARGS = {'HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'FTP_PROXY', 'ftp_proxy',
              'NO_PROXY', 'no_proxy', 'ALL_PROXY', 'all_proxy'}


class BuildError(Exception):
    pass


# ------------------------------------------------------------ parsing
class Instruction:
    def __init__(self, cmd, rest, line, heredocs=()):
        self.cmd, self.rest, self.line = cmd, rest, line
        self.heredocs = list(heredocs)   # (word, content)
        self.flags = {}
        self.flag_list = []
        while True:
            m = re.match(r'--([a-z-]+)(?:=(\S*))?\s*', self.rest)
            if not m or cmd not in ('FROM', 'COPY', 'ADD', 'RUN', 'HEALTHCHECK'):
                break
            self.flag_list.append((m.group(1), m.group(2) if m.group(2) is not None else 'true'))
            self.flags.setdefault(m.group(1), m.group(2) if m.group(2) is not None else 'true')
            self.rest = self.rest[m.end():]

    def json_form(self):
        text = self.rest.strip()
        if text.startswith('['):
            try:
                value = json.loads(text)
            except ValueError:
                return None
            if isinstance(value, list) and all(isinstance(v, str) for v in value):
                return value
        return None

    def __str__(self):
        flags = ''.join(f'--{k}={v} ' for k, v in self.flag_list)
        return f'{self.cmd} {flags}{self.rest}'.strip()


HEREDOC = re.compile(r'<<(-?)(["\']?)([A-Za-z_][A-Za-z0-9_]*)\2')


def parse_dockerfile(text):
    lines = text.splitlines()
    escape = '\\'
    i = 0
    # Parser directives: leading "# key=value" comments.
    while i < len(lines):
        m = re.match(r'^#\s*([a-zA-Z]+)\s*=\s*(\S+)\s*$', lines[i])
        if not m:
            break
        if m.group(1).lower() == 'escape':
            escape = m.group(2)
        i += 1
    out = []
    while i < len(lines):
        start = i + 1
        line = lines[i]
        i += 1
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        joined = ''
        while True:
            stripped = line.rstrip()
            if stripped.endswith(escape):
                joined += stripped[:-1]
                while i < len(lines) and (not lines[i].strip() or lines[i].lstrip().startswith('#')):
                    i += 1
                if i >= len(lines):
                    break
                line = lines[i]
                i += 1
                continue
            joined += line
            break
        parts = joined.strip().split(None, 1)
        cmd = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ''
        heredocs = []
        if cmd in ('RUN', 'COPY', 'ADD'):
            for m in HEREDOC.finditer(rest):
                strip_tabs, word = m.group(1) == '-', m.group(3)
                body = []
                while i < len(lines) and (lines[i].lstrip('\t') if strip_tabs else lines[i]) != word:
                    body.append(lines[i].lstrip('\t') if strip_tabs else lines[i])
                    i += 1
                if i >= len(lines):
                    raise BuildError(f'line {start}: unterminated heredoc {word}')
                i += 1
                heredocs.append((word, '\n'.join(body) + '\n', m.group(2) != ''))
        out.append(Instruction(cmd, rest, start, heredocs))
    return out


def expand(word, env, line=0):
    """Dockerfile variable substitution: $V, ${V}, ${V:-x}, ${V-x}, ${V:+x},
    ${V+x}, and \\$ for a literal dollar."""
    out = []
    i = 0
    while i < len(word):
        c = word[i]
        if c == '\\' and i + 1 < len(word) and word[i + 1] == '$':
            out.append('$')
            i += 2
            continue
        if c != '$':
            out.append(c)
            i += 1
            continue
        if i + 1 < len(word) and word[i + 1] == '{':
            end = word.find('}', i + 2)
            if end < 0:
                raise BuildError(f'line {line}: missing }} in {word}')
            body = word[i + 2:end]
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])(.*))?$', body, re.S)
            if not m:
                raise BuildError(f'line {line}: bad substitution ${{{body}}}')
            name, op, arg = m.groups()
            value = env.get(name)
            if op in (':-', '-'):
                if value is None or (op == ':-' and value == ''):
                    value = expand(arg, env, line)
            elif op in (':+', '+'):
                value = expand(arg, env, line) if value is not None and (op == '+' or value != '') else ''
            out.append(value or '')
            i = end + 1
            continue
        m = re.match(r'[A-Za-z_][A-Za-z0-9_]*', word[i + 1:])
        if m:
            out.append(env.get(m.group(0), ''))
            i += 1 + m.end()
        else:
            out.append('$')
            i += 1
    return ''.join(out)


def key_values(text, env, line, legacy=True):
    """ENV/LABEL: k=v pairs (quotes and escapes as a shell would), or the
    legacy "ENV k v w" form."""
    words = shlex.split(text, posix=True)
    if legacy and words and '=' not in words[0]:
        key, _, value = text.strip().partition(' ')
        return [(key, expand(value.strip(), env, line))]
    out = []
    for w in shlex.split(text, posix=True):
        if '=' not in w:
            raise BuildError(f'line {line}: expected KEY=VALUE, got {w}')
        k, _, v = w.partition('=')
        out.append((expand(k, env, line), expand(v, env, line)))
    return out


# ------------------------------------------------------------ context
class Ignore:
    """.dockerignore: Go filepath.Match patterns, ** for any directories,
    ! exceptions; the last matching pattern wins; a matching parent
    excludes its children."""

    def __init__(self, text):
        self.rules = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            negate = line.startswith('!')
            pattern = os.path.normpath(line[1:].strip() if negate else line).lstrip('/')
            self.rules.append((negate, re.compile('^' + self._regex(pattern) + '$')))

    @staticmethod
    def _regex(pattern):
        out = ''
        i = 0
        while i < len(pattern):
            c = pattern[i]
            if pattern.startswith('**', i):
                out += '.*'
                i += 2
                if i < len(pattern) and pattern[i] == '/':
                    out = out[:-2] + '(?:.*/)?'
                    i += 1
                continue
            if c == '*':
                out += '[^/]*'
            elif c == '?':
                out += '[^/]'
            elif c == '[':
                end = pattern.find(']', i)
                if end < 0:
                    out += re.escape(c)
                else:
                    cls = pattern[i + 1:end].replace('\\', '\\\\')
                    out += '[' + ('^' + cls[1:] if cls.startswith('^') else cls) + ']'
                    i = end
            else:
                out += re.escape(c)
            i += 1
        return out

    def excluded(self, rel):
        """Docker's MatchesOrParentMatches: a rule applies when it matches
        the path or one of its parents; the last applying rule decides."""
        rel = rel.strip('/')
        if not rel or not self.rules:
            return False
        parts = rel.split('/')
        prefixes = ['/'.join(parts[:n]) for n in range(1, len(parts) + 1)]
        result = False
        for negate, rx in self.rules:
            if any(rx.match(prefix) for prefix in prefixes):
                result = not negate
        return result


def hash_tree(path, ignore=None, base=None):
    """Content hash of a file or tree (names, modes, contents, links)."""
    h = hashlib.sha256()
    path = Path(path)
    base = base or path

    def add(p):
        rel = str(p.relative_to(base)) if p != base else '.'
        if ignore and rel != '.' and ignore.excluded(rel):
            return
        st = os.lstat(p)
        h.update(f'{rel}\0{st.st_mode:o}\0'.encode())
        if p.is_symlink():
            h.update(os.readlink(p).encode())
        elif p.is_dir():
            for child in sorted(os.listdir(p)):
                add(p / child)
        else:
            with open(p, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
    add(path)
    return h.hexdigest()


def copy_into(src, dest, ignore=None, base=None, chmod=None):
    """Copies a file or a directory's contents to dest (a path that may not
    exist); symlinks stay symlinks."""
    src = Path(src)
    base = base or src
    if src.is_symlink() or not src.is_dir():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
            dest.unlink()
        elif dest.is_dir():
            store_mod.remove(dest)
        if src.is_symlink():
            os.symlink(os.readlink(src), dest)
        else:
            shutil.copy2(src, dest)
            if chmod is not None:
                os.chmod(dest, chmod)
        return
    if dest.is_symlink() or (dest.exists() and not dest.is_dir()):
        dest.unlink()
    dest.mkdir(parents=True, exist_ok=True)
    for child in sorted(os.listdir(src)):
        s = src / child
        rel = str(s.relative_to(base))
        if ignore and ignore.excluded(rel):
            continue
        copy_into(s, dest / child, ignore, base, chmod)
    shutil.copystat(src, dest)


# ------------------------------------------------------------ stages
class Stage:
    def __init__(self, index, name):
        self.index, self.name = index, name
        self.rootfs = None
        self.base_id = None
        self.config = {}
        self.layers = []          # descriptors (mediaType, digest, size)
        self.diff_ids = []
        self.history = []
        self.args = {}
        self.key = ''
        self.snapshot = None
        self.meta = {'owners': {}, 'modes': {}, 'hardlinks': {}, 'skipped': {}}
        self.instructions = []
        self.created = None

    @property
    def env(self):
        out = {}
        for entry in self.config.get('Env') or []:
            k, _, v = entry.partition('=')
            out[k] = v
        return out

    def set_env(self, key, value):
        env = [e for e in self.config.get('Env') or [] if e.partition('=')[0] != key]
        env.append(f'{key}={value}')
        self.config['Env'] = env

    def scope(self):
        """Variables for substitution: ARGs then ENV (ENV wins)."""
        return {**self.args, **self.env}


class Builder:
    def __init__(self, st, context, dockerfile_text, args, quiet=False, no_cache=False,
                 pull='missing', target=None, secrets=None, isolate=False, labels=None):
        self.st = st
        self.context = Path(context) if context else None
        self.instructions = parse_dockerfile(dockerfile_text)
        self.build_args = args
        self.used_args = set()
        self.quiet, self.no_cache, self.pull = quiet, no_cache, pull
        self.target, self.secrets, self.isolate = target, secrets or {}, isolate
        self.labels = labels or {}
        self.work = st.tmpdir('build')
        self.ignore = None
        if self.context and (self.context / '.dockerignore').exists():
            self.ignore = Ignore((self.context / '.dockerignore').read_text())
        self.stages = []
        self.step = 0

    def say(self, text):
        if not self.quiet:
            print(text, flush=True)

    def close(self):
        if self.work.exists():
            store_mod.remove(self.work)

    # Stage graph: only what the target needs is built.
    def split_stages(self):
        global_args = {}
        stages, current = [], None
        for ins in self.instructions:
            if ins.cmd == 'FROM':
                words = ins.rest.split()
                name = words[2].lower() if len(words) >= 3 and words[1].upper() == 'AS' else None
                current = Stage(len(stages), name)
                current.from_ins = ins
                stages.append(current)
            elif current is None:
                if ins.cmd != 'ARG':
                    raise BuildError(f'line {ins.line}: {ins.cmd} before FROM')
                for word in shlex.split(ins.rest):
                    k, eq, v = word.partition('=')
                    global_args[k] = self.build_args.get(k, v if eq else None)
                    self.used_args.add(k)
            else:
                current.instructions.append(ins)
        if not stages:
            raise BuildError('the Dockerfile has no FROM')
        self.global_args = {k: v for k, v in global_args.items() if v is not None}
        self.global_args.update({k: v for k, v in PLATFORM_ARGS.items() if k not in self.global_args})
        self.stages = stages
        return stages

    def stage_ref(self, text):
        for s in self.stages:
            if s.name == text.lower():
                return s
        if text.isdigit() and int(text) < len(self.stages):
            return self.stages[int(text)]
        return None

    def needed(self, target):
        need, todo = set(), [target]
        while todo:
            s = todo.pop()
            if s.index in need:
                continue
            need.add(s.index)
            base = expand(s.from_ins.rest.split()[0], self.global_args)
            ref = self.stage_ref(base)
            if ref and ref.index < s.index:
                todo.append(ref)
            for ins in s.instructions:
                refs = [v for k, v in ins.flag_list if k == 'from']
                refs += re.findall(r'from=([^,\s]+)', ' '.join(v for k, v in ins.flag_list if k == 'mount'))
                for r in refs:
                    ref = self.stage_ref(r)
                    if ref and ref.index < s.index:
                        todo.append(ref)
        return need

    def run(self):
        stages = self.split_stages()
        target = stages[-1]
        if self.target:
            target = self.stage_ref(self.target)
            if target is None:
                raise BuildError(f'target stage "{self.target}" could not be found')
        need = self.needed(target)
        total = sum(1 + len(s.instructions) for s in stages if s.index in need)
        self.total = total
        for s in stages:
            if s.index in need:
                self.build_stage(s)
            if s is target:
                break
        unused = set(self.build_args) - self.used_args - PROXY_ARGS
        if unused and not self.quiet:
            print(f'[Warning] One or more build-args {sorted(unused)} were not consumed', file=sys.stderr)
        return self.finish(target)

    def header(self, ins):
        self.step += 1
        self.say(f'Step {self.step}/{self.total} : {ins}')

    # FROM.
    def build_stage(self, s):
        ins = s.from_ins
        self.header(ins)
        words = ins.rest.split()
        base = expand(words[0], self.global_args, ins.line)
        platform = ins.flags.get('platform')
        if platform and expand(platform, self.global_args) not in ('linux/arm64', 'linux/arm64/v8'):
            raise BuildError(f'line {ins.line}: only linux/arm64 bases can be built here')
        s.rootfs = self.work / f'stage{s.index}'
        ref = self.stage_ref(base)
        if ref is not None and ref.index < s.index:
            runspec.copy_rootfs(ref.rootfs, s.rootfs)
            s.config = json.loads(json.dumps(ref.config))
            s.layers, s.diff_ids = list(ref.layers), list(ref.diff_ids)
            s.history, s.meta = list(ref.history), json.loads(json.dumps(ref.meta))
            s.key = hashlib.sha256(f'stage:{ref.key}'.encode()).hexdigest()
            onbuild = []
        elif base == 'scratch':
            s.rootfs.mkdir()
            s.key = hashlib.sha256(b'scratch').hexdigest()
            onbuild = []
        else:
            import importlib
            docker = importlib.import_module('docker_cli')
            image_id = docker.ensure_image(self.st, base, self.pull, quiet=self.quiet)
            info = self.st.image_info(image_id)
            runspec.copy_rootfs(self.st.image_dir(image_id) / 'rootfs', s.rootfs)
            s.base_id = image_id
            s.config = json.loads(json.dumps(info['config'].get('config', {})))
            s.layers = list(info['manifest'].get('layers', []))
            s.diff_ids = list(info['config'].get('rootfs', {}).get('diff_ids', []))
            s.history = list(info['config'].get('history', []))
            s.meta = store_mod.read_json(self.st.image_dir(image_id) / 'meta.json', s.meta)
            s.key = hashlib.sha256(f'image:{image_id}'.encode()).hexdigest()
            onbuild = s.config.pop('OnBuild', None) or []
            self.say(f' ---> {image_id[:12]}')
        s.config.pop('OnBuild', None)
        s.args = dict(PLATFORM_ARGS)
        for trigger in onbuild:
            self.say(f'# Executing ONBUILD trigger: {trigger}')
            for t in parse_dockerfile(trigger):
                self.instruction(s, t)
        for i in s.instructions:
            self.header(i)
            self.instruction(s, i)

    # One instruction.
    def instruction(self, s, ins):
        handler = getattr(self, 'do_' + ins.cmd, None)
        if handler is None:
            raise BuildError(f'line {ins.line}: unknown instruction {ins.cmd}')
        scope = s.scope()
        if ins.cmd in FS_INSTRUCTIONS:
            extra, prepare = handler(s, ins, scope, plan=True)
            text = f'{ins}\0{extra}'
            if ins.cmd == 'RUN':
                # Build args in effect change RUN's environment, so its key.
                text += '\0' + json.dumps(sorted(s.args.items()))
            key = hashlib.sha256(f'{s.key}\0{text}'.encode()).hexdigest()
            cached = None if self.no_cache else store_mod.read_json(
                self.st.home / 'build-cache' / f'{key}.json', {}) or None
            if cached and (cached.get('layer') is None or self.st.blob(cached['layer']['digest']).exists()):
                self.say(' ---> Using cache')
                if cached.get('layer'):
                    extractor = unpack.Extractor(s.rootfs)
                    extractor.meta = s.meta  # the layer's owners and modes
                    try:
                        extractor.layer(self.st.blob(cached['layer']['digest']))
                    finally:
                        extractor.close()
                    s.layers.append(cached['layer'])
                    s.diff_ids.append(cached['diff_id'])
                    s.snapshot = None
                s.history.append(cached['history'])
            else:
                if s.snapshot is None:
                    s.snapshot = layers.scan(s.rootfs)
                meta_before = json.loads(json.dumps(s.meta))
                prepare()
                after = layers.scan(s.rootfs)
                changed, deleted = layers.changes(s.snapshot, after)
                # chown/chmod alone (R5) change a path for the layer too.
                changed = sorted(set(changed) | {p for p in layers.owner_changes(meta_before, s.meta)
                                                 if p in after})
                created = store_mod.now()
                history = {'created': created, 'created_by': self.created_by(ins),
                           'comment': 'elf-oci build'}
                entry = {'history': history}
                if changed or deleted:
                    plain = self.work / f'layer-{key}.tar'
                    diff_id = layers.write_layer(s.rootfs, changed, deleted, plain, s.meta.get('modes'),
                                                 s.meta.get('owners'))
                    digest, size = layers.compress(self.st, plain)
                    plain.unlink()
                    layer = {'mediaType': images.OCI_LAYER_GZIP, 'digest': digest, 'size': size}
                    s.layers.append(layer)
                    s.diff_ids.append(diff_id)
                    entry.update(layer=layer, diff_id=diff_id)
                else:
                    history['empty_layer'] = True
                    entry['layer'] = None
                s.history.append(history)
                s.snapshot = after
                store_mod.write_json(self.st.home / 'build-cache' / f'{key}.json', entry)
            s.key = key
        else:
            handler(s, ins, scope)
            s.key = hashlib.sha256(f'{s.key}\0{ins}\0{json.dumps(s.config, sort_keys=True)}'.encode()).hexdigest()
            if ins.cmd not in ('ARG',):
                s.history.append({'created': store_mod.now(), 'created_by': self.created_by(ins),
                                  'comment': 'elf-oci build', 'empty_layer': True,
                                  'cache': True})

    @staticmethod
    def created_by(ins):
        if ins.cmd == 'RUN':
            form = ins.json_form()
            return 'RUN ' + (' '.join(form) if form else f'/bin/sh -c {ins.rest}')
        return str(ins)

    # Metadata instructions.
    def do_ENV(self, s, ins, scope):
        for k, v in key_values(ins.rest, scope, ins.line):
            s.set_env(k, v)
            scope[k] = v

    def do_ARG(self, s, ins, scope):
        for word in shlex.split(ins.rest):
            k, eq, v = word.partition('=')
            self.used_args.add(k)
            if k in self.build_args:
                s.args[k] = self.build_args[k]
            elif eq:
                s.args[k] = expand(v, scope, ins.line)
            elif k in self.global_args:
                s.args[k] = self.global_args[k]
            elif k in PLATFORM_ARGS:
                s.args[k] = PLATFORM_ARGS[k]

    def do_LABEL(self, s, ins, scope):
        labels = s.config.setdefault('Labels', {}) or {}
        for k, v in key_values(ins.rest, scope, ins.line, legacy=False):
            labels[k] = v
        s.config['Labels'] = labels

    def do_MAINTAINER(self, s, ins, scope):
        s.author = ins.rest.strip()

    def exec_form(self, s, ins):
        form = ins.json_form()
        if form is not None:
            return form
        return (s.config.get('Shell') or DEFAULT_SHELL) + [ins.rest.strip()]

    def do_CMD(self, s, ins, scope):
        s.config['Cmd'] = self.exec_form(s, ins)
        s.cmd_set = True

    def do_ENTRYPOINT(self, s, ins, scope):
        s.config['Entrypoint'] = self.exec_form(s, ins)
        if not getattr(s, 'cmd_set', False):
            s.config['Cmd'] = None   # An inherited CMD does not survive.

    def do_SHELL(self, s, ins, scope):
        form = ins.json_form()
        if not form:
            raise BuildError(f'line {ins.line}: SHELL requires the JSON form')
        s.config['Shell'] = form

    def do_USER(self, s, ins, scope):
        s.config['User'] = expand(ins.rest.strip(), scope, ins.line)

    def do_EXPOSE(self, s, ins, scope):
        ports = s.config.setdefault('ExposedPorts', {}) or {}
        for p in expand(ins.rest, scope, ins.line).split():
            ports[p if '/' in p else p + '/tcp'] = {}
        s.config['ExposedPorts'] = ports

    def do_VOLUME(self, s, ins, scope):
        vols = s.config.setdefault('Volumes', {}) or {}
        for v in ins.json_form() or expand(ins.rest, scope, ins.line).split():
            vols[v] = {}
        s.config['Volumes'] = vols

    def do_STOPSIGNAL(self, s, ins, scope):
        s.config['StopSignal'] = expand(ins.rest.strip(), scope, ins.line)

    def do_ONBUILD(self, s, ins, scope):
        s.config['OnBuild'] = (s.config.get('OnBuild') or []) + [ins.rest.strip()]

    def do_HEALTHCHECK(self, s, ins, scope):
        rest = ins.rest.strip()
        if rest.upper() == 'NONE':
            s.config['Healthcheck'] = {'Test': ['NONE']}
            return
        if not rest.upper().startswith('CMD'):
            raise BuildError(f'line {ins.line}: HEALTHCHECK needs CMD or NONE')
        sub = Instruction('CMD', rest[3:].strip(), ins.line)
        form = sub.json_form()
        check = {'Test': ['CMD'] + form if form else ['CMD-SHELL', sub.rest]}
        units = {'s': 1e9, 'ms': 1e6, 'm': 60e9, 'h': 3600e9}
        for k, v in ins.flags.items():
            field = {'interval': 'Interval', 'timeout': 'Timeout', 'start-period': 'StartPeriod',
                     'start-interval': 'StartInterval', 'retries': 'Retries'}.get(k)
            if field == 'Retries':
                check[field] = int(v)
            elif field:
                m = re.match(r'^([\d.]+)(ms|s|m|h)$', v)
                if not m:
                    raise BuildError(f'line {ins.line}: bad duration {v}')
                check[field] = int(float(m.group(1)) * units[m.group(2)])
        s.config['Healthcheck'] = check

    # File system instructions: (cache extra, action).
    def do_WORKDIR(self, s, ins, scope, plan=False):
        path = expand(ins.rest.strip(), scope, ins.line)
        path = str(PurePosixPath(s.config.get('WorkingDir') or '/', path))
        s.config['WorkingDir'] = path   # Also on a cache hit.

        def act():
            runspec.make_guest_dirs(s.rootfs, [], path)
        return '', act

    def do_RUN(self, s, ins, scope, plan=False):
        form = ins.json_form()
        if form is None and ins.heredocs and re.fullmatch(r'\s*<<-?(["\']?)\w+\1\s*', ins.rest):
            command = (s.config.get('Shell') or DEFAULT_SHELL) + [ins.heredocs[0][1]]
        elif form is None:
            text = ins.rest
            if ins.heredocs:
                text += '\n' + ''.join(body + word + '\n' for word, body, _ in ins.heredocs)
            command = (s.config.get('Shell') or DEFAULT_SHELL) + [text]
        else:
            command = form
        network = ins.flags.get('network', 'default')
        if network not in ('default', 'host'):
            raise BuildError(f'line {ins.line}: RUN --network={network} is not supported (host network only)')
        mounts = [self.mount_spec(v, s, ins) for k, v in ins.flag_list if k == 'mount']
        extra = json.dumps([m['key'] for m in mounts])

        def act():
            cdir = self.work / f'run-{s.index}-{self.step}'
            cdir.mkdir()
            runspec.write_etc(cdir, 'buildkitsandbox')
            binds = [m['bind'](cdir) for m in mounts]
            env = [f'{k}={v}' for k, v in s.args.items()] + list(s.config.get('Env') or [])
            record = {'Config': {'Hostname': 'buildkitsandbox', 'User': s.config.get('User', ''),
                                 'Env': env, 'WorkingDir': s.config.get('WorkingDir') or '/'},
                      'HostConfig': {'Binds': binds, 'Owners': True}}
            runspec.install_helper(s.rootfs)
            # R5: chown/chmod in RUN are recorded and go into the layer.
            owners_mod.from_meta(s.rootfs, s.meta, cdir / 'owners.db')
            argv, _ = runspec.build(record, s.rootfs, cdir, isolate=self.isolate, command=command)
            proc = subprocess.run(argv, cwd=str(s.rootfs), stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL if self.quiet else None,
                                  env={'PATH': os.environ.get('PATH', '/usr/bin:/bin')})
            (s.rootfs / runspec.HELPER).unlink(missing_ok=True)
            if not proc.returncode:
                owners_mod.update_meta(s.meta, owners_mod.guest_view(s.rootfs, cdir / 'owners.db'))
            store_mod.remove(cdir)
            if proc.returncode:
                shown = json.dumps(command) if form else ' '.join(command[:-1]) + ' ' + command[-1]
                raise BuildError(f"The command '{shown}' returned a non-zero code: {proc.returncode}")
        return extra, act

    def mount_spec(self, text, s, ins):
        fields = {}
        for item in text.split(','):
            k, _, v = item.partition('=')
            fields[k] = v if v else 'true'
        kind = fields.get('type', 'bind')
        target = fields.get('target') or fields.get('dst') or fields.get('destination')
        if kind == 'secret':
            sid = fields.get('id') or os.path.basename(target or '')
            target = target or f'/run/secrets/{sid}'
            source = self.secrets.get(sid)
            if source is None:
                if fields.get('required') in ('true', '1'):
                    raise BuildError(f'line {ins.line}: secret {sid} not provided (--secret id={sid},src=...)')
                return {'key': f'secret:{sid}:none', 'bind': lambda cdir: None}

            def bind(cdir, source=source, sid=sid, target=target):
                d = cdir / 'secrets'
                d.mkdir(exist_ok=True)
                path = d / sid
                if source[0] == 'env':
                    path.write_text(os.environ.get(source[1], ''))
                else:
                    shutil.copyfile(source[1], path)
                return (str(path), target, 'rw')
            return {'key': f'secret:{sid}', 'bind': bind}
        if not target:
            raise BuildError(f'line {ins.line}: --mount needs target=')
        target = str(PurePosixPath(s.config.get('WorkingDir') or '/', target))
        if kind == 'cache':
            cid = fields.get('id') or target
            d = self.st.home / 'build-cache' / 'mounts' / hashlib.sha256(cid.encode()).hexdigest()[:24]

            def bind(cdir, d=d):
                d.mkdir(parents=True, exist_ok=True)
                return (str(d), target, 'rw')
            return {'key': f'cache:{target}', 'bind': bind}
        if kind == 'tmpfs':
            def bind(cdir):
                d = cdir / f'tmpfs{abs(hash(target))}'
                d.mkdir()
                return (str(d), target, 'rw')
            return {'key': f'tmpfs:{target}', 'bind': bind}
        if kind == 'bind':
            src_root, ignore = self.source_root(fields.get('from'), ins)
            src = self.source_path(src_root, fields.get('source') or fields.get('src') or '.', ins)
            content = hash_tree(src, ignore if src_root == self.context else None)

            def bind(cdir, src=src, ignore=ignore):
                # A copy: writes in the RUN never reach the source.
                d = cdir / f'bind{abs(hash(target))}'
                copy_into(src, d, ignore if src_root == self.context else None)
                return (str(d), target, 'rw')
            return {'key': f'bind:{target}:{content}', 'bind': bind}
        raise BuildError(f'line {ins.line}: --mount type={kind} is not supported')

    def source_root(self, ref, ins):
        """Root of COPY/mount sources: the context, a stage, or an image."""
        if not ref:
            if self.context is None:
                raise BuildError(f'line {ins.line}: no build context (Dockerfile from stdin)')
            return self.context, self.ignore
        stage = self.stage_ref(ref)
        if stage is not None and stage.rootfs is not None:
            return stage.rootfs, None
        import importlib
        docker = importlib.import_module('docker_cli')
        image_id = docker.ensure_image(self.st, ref, self.pull, quiet=self.quiet)
        return self.st.image_dir(image_id) / 'rootfs', None

    def source_path(self, root, path, ins):
        if root == self.context:
            rel = os.path.normpath(path).lstrip('/')
            if rel.startswith('..'):
                raise BuildError(f'line {ins.line}: {path} is outside the build context')
            p = root / rel
            if not p.exists() and not p.is_symlink():
                raise BuildError(f'line {ins.line}: "{path}" not found in the build context')
            return p
        p = runspec.guest_resolve(root, [], path)
        if not p.exists():
            raise BuildError(f'line {ins.line}: "{path}" not found')
        return p

    def sources(self, root, words, ins, ignore):
        """Wildcards expanded; each existing source path."""
        out = []
        for w in words:
            if root == self.context and re.search(r'[*?\[]', w):
                pattern = os.path.normpath(w).lstrip('/')
                matches = []
                for top, dirs, files in os.walk(root):
                    for name in dirs + files:
                        rel = os.path.relpath(os.path.join(top, name), root)
                        if fnmatch.fnmatchcase(rel, pattern) and not (ignore and ignore.excluded(rel)):
                            matches.append(Path(root, rel))
                if not matches:
                    raise BuildError(f'line {ins.line}: no source files were specified by {w}')
                out += sorted(matches)
            else:
                out.append(self.source_path(root, w, ins))
        return out

    def chown_copied(self, s, ins, scope, targets):
        """COPY --chown (R5): the copied files' owner, in the stage's meta."""
        spec = ins.flags.get('chown')
        if not spec:
            return
        try:
            uid, gid, _ = runspec.resolve_user(s.rootfs, expand(spec, scope, ins.line))
        except runspec.SpecError as e:
            raise BuildError(f'line {ins.line}: --chown: {e}') from None
        if ':' not in spec:
            gid = uid  # Docker: without a group, the GID is the UID
        root = str(s.rootfs)
        owners = s.meta.setdefault('owners', {})
        for target in targets:
            host = str(target)
            for path in [host] + [os.path.join(d, n) for d, ds, fs in os.walk(host) for n in ds + fs]:
                guest = path[len(root):] or '/'
                if uid or gid:
                    owners[guest] = [uid, gid]
                else:
                    owners.pop(guest, None)

    def do_COPY(self, s, ins, scope, plan=False, add=False):
        chmod = int(ins.flags['chmod'], 8) if 'chmod' in ins.flags else None
        if 'parents' in ins.flags:
            raise BuildError(f'line {ins.line}: COPY --parents is not supported')
        form = ins.json_form()
        words = form if form is not None else shlex.split(ins.rest)
        words = [expand(w, scope, ins.line) for w in words]
        if ins.heredocs:
            dest = words[-1]
            docs = [(w, body) for w, body, _ in ins.heredocs]
            dest_path = str(PurePosixPath(s.config.get('WorkingDir') or '/', dest))
            extra = hashlib.sha256(json.dumps(docs).encode()).hexdigest()

            def act():
                for word, body in docs:
                    target = dest_path if len(docs) == 1 and not dest.endswith('/') else \
                        str(PurePosixPath(dest_path, word))
                    host = runspec.guest_resolve(s.rootfs, [], target)
                    host.parent.mkdir(parents=True, exist_ok=True)
                    host.write_text(body)
                    if chmod is not None:
                        os.chmod(host, chmod)
                    self.chown_copied(s, ins, scope, [host])
            return extra, act
        if len(words) < 2:
            raise BuildError(f'line {ins.line}: {ins.cmd} requires at least two arguments')
        srcs, dest = words[:-1], words[-1]
        dest_path = str(PurePosixPath(s.config.get('WorkingDir') or '/', dest))
        urls = [w for w in srcs if re.match(r'^https?://', w)]
        if urls and not add:
            raise BuildError(f'line {ins.line}: COPY cannot fetch URLs; use ADD')
        local = [w for w in srcs if w not in urls]
        root, ignore = self.source_root(ins.flags.get('from'), ins) if local else (None, None)
        if ins.flags.get('exclude'):
            extra_rules = '\n'.join(v for k, v in ins.flag_list if k == 'exclude')
            ignore = Ignore(((self.context / '.dockerignore').read_text() + '\n'
                             if ignore is not None and self.context else '') + extra_rules)
        paths = self.sources(root, local, ins, ignore if root == self.context else ignore) if local else []
        many = len(paths) + len(urls) > 1
        if many and not dest.endswith('/'):
            raise BuildError(f'line {ins.line}: When using {ins.cmd} with more than one source file, '
                             'the destination must be a directory and end with a /')
        hashes = [hash_tree(p, ignore if root == self.context else None,
                            root if root == self.context else None) for p in paths]
        extra = json.dumps([hashes, urls, ins.flags.get('checksum')])

        def act():
            copied = []
            for p in paths:
                host_dest = runspec.guest_resolve(s.rootfs, [], dest_path)
                if add and p.is_file() and not p.is_symlink() and is_archive(p):
                    host_dest.mkdir(parents=True, exist_ok=True)
                    extract_archive(p, host_dest)
                    continue
                if p.is_dir() and not p.is_symlink():
                    copy_into(p, host_dest, ignore if root == self.context else None,
                              root if root == self.context else p, chmod)
                    copied.append(host_dest)
                else:
                    target = host_dest / p.name if (dest.endswith('/') or host_dest.is_dir()) else host_dest
                    copy_into(p, target, chmod=chmod)
                    copied.append(target)
            self.chown_copied(s, ins, scope, copied)
            for url in urls:
                host_dest = runspec.guest_resolve(s.rootfs, [], dest_path)
                name = os.path.basename(url.split('?')[0]) or 'download'
                target = host_dest / name if (dest.endswith('/') or host_dest.is_dir()) else host_dest
                target.parent.mkdir(parents=True, exist_ok=True)
                with urllib.request.urlopen(url, timeout=300) as r, open(target, 'wb') as f:
                    shutil.copyfileobj(r, f)
                if ins.flags.get('checksum'):
                    actual = images.sha256_file(target)
                    if actual != ins.flags['checksum']:
                        raise BuildError(f'line {ins.line}: checksum of {url} is {actual}')
                os.chmod(target, chmod if chmod is not None else 0o600)
                self.chown_copied(s, ins, scope, [target])
        return extra, act

    def do_ADD(self, s, ins, scope, plan=False):
        if any(w.startswith('git@') or w.endswith('.git') for w in shlex.split(ins.rest)):
            raise BuildError(f'line {ins.line}: ADD of git repositories is not supported')
        return self.do_COPY(s, ins, scope, plan, add=True)

    # Result.
    def finish(self, s):
        config = dict(s.config)
        if self.labels:
            config['Labels'] = {**(config.get('Labels') or {}), **self.labels}
        # Reproducible for a fully cached build: the newest history time.
        created = max((h.get('created', '') for h in s.history if not h.get('cache')), default=store_mod.now())
        history = [{k: v for k, v in h.items() if k != 'cache'} for h in s.history]
        for h in history:
            if h.get('comment') == 'elf-oci build' and h.get('empty_layer') and 'created' in h:
                h['created'] = created
        image_config = {'architecture': 'arm64', 'os': 'linux', 'created': created,
                        'config': config, 'rootfs': {'type': 'layers', 'diff_ids': s.diff_ids},
                        'history': history}
        if getattr(s, 'author', None):
            image_config['author'] = s.author
        config_bytes = json.dumps(image_config, separators=(',', ':')).encode()
        manifest = {'schemaVersion': 2, 'mediaType': images.OCI_MANIFEST,
                    'config': {'mediaType': images.OCI_CONFIG, 'size': len(config_bytes),
                               'digest': 'sha256:' + hashlib.sha256(config_bytes).hexdigest()},
                    'layers': s.layers}
        return install_built(self.st, config_bytes, manifest, s.rootfs, s.meta)


def install_built(st, config_bytes, manifest, rootfs, meta):
    """Moves a finished rootfs into the store as an image (no re-unpack)."""
    digest = images.put_blob(st, config_bytes)
    images.put_blob(st, json.dumps(manifest, separators=(',', ':')).encode())
    image_id = digest[7:]
    target = st.image_dir(image_id)
    if (target / 'config.json').exists():
        return image_id
    work = st.tmpdir('image')
    try:
        helper = Path(rootfs) / runspec.HELPER
        if helper.exists():
            helper.unlink()
        os.rename(rootfs, work / 'rootfs')
        store_mod.write_json(work / 'meta.json', meta)
        store_mod.write_json(work / 'manifest.json', manifest)
        store_mod.write_json(work / 'info.json', {
            'created': store_mod.now(), 'repo_digests': [],
            'size': store_mod.tree_size(work / 'rootfs'),
            'layer_digests': [l['digest'] for l in manifest['layers']]})
        (work / 'config.json').write_bytes(config_bytes)
        with st.lock():
            if not (target / 'config.json').exists():
                work.rename(target)
    finally:
        if work.exists():
            store_mod.remove(work)
    return image_id


def is_archive(path):
    with open(path, 'rb') as f:
        head = f.read(262)
    return (head[:2] == b'\x1f\x8b' or head[:3] == b'BZh' or head[:6] == b'\xfd7zXZ\x00'
            or head[:4] == b'\x28\xb5\x2f\xfd' or head[257:262] == b'ustar')


def extract_archive(path, dest):
    """ADD of a local tar: extracted with the layer extractor's safety."""
    import bz2
    import lzma
    with open(path, 'rb') as f:
        head = f.read(6)
    if head[:3] == b'BZh':
        fileobj = bz2.open(path)
    elif head == b'\xfd7zXZ\x00':
        fileobj = lzma.open(path)
    else:
        fileobj = unpack.open_layer(path)
    import tarfile
    extractor = unpack.Extractor(dest)
    try:
        with tarfile.open(fileobj=fileobj, mode='r|') as tar:
            touched, times = set(), []
            for m in tar:
                extractor.member(tar, m, touched, times)
    finally:
        extractor.close()
        fileobj.close()


# ------------------------------------------------------------ commands
def cli():
    """The docker command module (registered by it as docker_cli)."""
    import importlib.util
    if 'docker_cli' in sys.modules:
        return sys.modules['docker_cli']
    import importlib.machinery
    loader = importlib.machinery.SourceFileLoader('docker_cli', str(Path(__file__).parent / 'docker'))
    spec = importlib.util.spec_from_loader('docker_cli', loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules['docker_cli'] = module
    loader.exec_module(module)
    return module


def tag_image(st, image_id, tags):
    for t in tags:
        ref = registry.Reference(t)
        st.set_ref(ref.full, image_id)


def cmd_build(st, args):
    docker = cli()
    p = docker.parser('build', 'Build an image from a Dockerfile')
    p.add_argument('-t', '--tag', action='append', default=[])
    p.add_argument('-f', '--file')
    p.add_argument('--build-arg', action='append', default=[])
    p.add_argument('--target')
    p.add_argument('--no-cache', action='store_true')
    p.add_argument('--pull', action='store_true')
    p.add_argument('-q', '--quiet', action='store_true')
    p.add_argument('--platform')
    p.add_argument('--secret', action='append', default=[])
    p.add_argument('--label', action='append', default=[])
    p.add_argument('--iidfile')
    p.add_argument('--progress')
    p.add_argument('--network', default='default')
    p.add_argument('--load', action='store_true')
    p.add_argument('--isolate', action='store_true', help='run RUN steps under the isolation broker (ELF)')
    p.add_argument('-o', '--output')
    p.add_argument('context')
    a = p.parse_args(args)
    if a.platform and a.platform not in ('linux/arm64', 'linux/arm64/v8'):
        raise docker.Fail(f'only linux/arm64 images can be built here, not {a.platform}')
    if a.network not in ('default', 'host'):
        raise docker.Fail('--network: only the host network exists')
    build_args = {}
    for item in a.build_arg:
        k, eq, v = item.partition('=')
        if eq:
            build_args[k] = v
        elif k in os.environ:
            build_args[k] = os.environ[k]
    secrets = {}
    for item in a.secret:
        fields = dict(f.partition('=')[::2] for f in item.split(','))
        sid = fields.get('id')
        if 'env' in fields:
            secrets[sid] = ('env', fields['env'])
        else:
            src = fields.get('src') or fields.get('source')
            if not sid or not src:
                raise docker.Fail(f'invalid secret {item}: need id= and src= (or env=)')
            secrets[sid] = ('file', os.path.expanduser(src))
    context = None
    if a.context == '-':
        dockerfile = sys.stdin.read()
    else:
        if re.match(r'^(https?|git)://', a.context):
            raise docker.Fail('remote build contexts are not supported')
        context = Path(a.context).resolve()
        if not context.is_dir():
            raise docker.Fail(f'unable to prepare context: path "{a.context}" not found')
        if a.file == '-':
            dockerfile = sys.stdin.read()
        else:
            path = Path(a.file) if a.file else context / 'Dockerfile'
            if not path.exists() and not a.file and (context / 'dockerfile').exists():
                path = context / 'dockerfile'
            if not path.exists():
                raise docker.Fail(f'failed to read dockerfile: open {path}: no such file or directory')
            dockerfile = path.read_text()
    labels = dict(l.partition('=')[::2] for l in a.label)
    builder = Builder(st, context, dockerfile, build_args, quiet=a.quiet, no_cache=a.no_cache,
                      pull='always' if a.pull else 'missing', target=a.target, secrets=secrets,
                      isolate=a.isolate, labels=labels)
    try:
        image_id = builder.run()
    except BuildError as e:
        print(f'ERROR: {e}', file=sys.stderr)
        return 1
    finally:
        builder.close()
    tag_image(st, image_id, a.tag)
    if a.output:
        export(st, image_id, a.output)
    if a.iidfile:
        Path(a.iidfile).write_text('sha256:' + image_id)
    if a.quiet:
        print('sha256:' + image_id)
    else:
        print(f'Successfully built {image_id[:12]}')
        for t in a.tag:
            print(f'Successfully tagged {t}')
    return 0


def export(st, image_id, spec):
    """--output type=local,dest=DIR | type=tar,dest=FILE | DIR."""
    fields = dict(f.partition('=')[::2] for f in spec.split(',')) if '=' in spec else {'type': 'local', 'dest': spec}
    kind, dest = fields.get('type', 'local'), fields.get('dest')
    root = st.image_dir(image_id) / 'rootfs'
    if kind == 'local':
        copy_into(root, Path(dest))
        helper = Path(dest) / runspec.HELPER
        if helper.exists():
            helper.unlink()
    elif kind == 'tar':
        import tarfile
        with tarfile.open(dest, 'w') as tar:
            for child in sorted(os.listdir(root)):
                if child != runspec.HELPER:
                    tar.add(str(root / child), child)
    elif kind in ('docker', 'oci'):
        with open(dest, 'wb') as out:
            images.save(st, [(image_id, st.image_names(image_id))], out)
    else:
        raise StoreError(f'unsupported output type {kind}')


def container_diff(st, record):
    host = record['HostConfig']
    if host.get('InPlace'):
        raise StoreError('an --in-place container has no unchanged image to compare with')
    if host.get('ReadonlyRootfs'):
        return {}, {}, None
    image_root = st.image_dir(record['Image']) / 'rootfs'
    container_root = runtime.rootfs_of(st, record)
    return layers.scan(image_root), layers.scan(container_root), container_root


def container_meta(st, record, root):
    """(image meta, the container's meta): with an owner database (R5)
    its owners and modes, else the image's."""
    meta = store_mod.read_json(st.image_dir(record['Image']) / 'meta.json', {})
    db = st.container_dir(record['Id']) / 'owners.db'
    new = json.loads(json.dumps(meta))
    if root is not None and db.exists():
        owners_mod.update_meta(new, owners_mod.guest_view(root, db))
    return meta, new


def cmd_diff(st, args):
    docker = cli()
    p = docker.parser('diff', 'Inspect changes to files or directories on a container\'s filesystem')
    p.add_argument('container')
    a = p.parse_args(args)
    record = st.resolve_container(a.container)
    before, after, root = container_diff(st, record)
    meta, new = container_meta(st, record, root)
    shown = layers.kinds(before, after)
    known = {path for _, path in shown}
    extra = [('C', p) for p in layers.owner_changes(meta, new) if p in after and p not in known]
    for kind, path in sorted(shown + extra, key=lambda x: x[1]):
        print(kind, path)


def cmd_commit(st, args):
    docker = cli()
    p = docker.parser('commit', 'Create a new image from a container\'s changes')
    p.add_argument('-a', '--author', default='')
    p.add_argument('-m', '--message', default='')
    p.add_argument('-c', '--change', action='append', default=[])
    p.add_argument('-p', '--pause', default='true')
    p.add_argument('container')
    p.add_argument('repository', nargs='?')
    a = p.parse_args(args)
    record = runtime.refresh(st, st.resolve_container(a.container))
    base = st.image_info(record['Image'])
    before, after, root = container_diff(st, record)
    changed, deleted = layers.changes(before, after)
    meta, new_meta = container_meta(st, record, root)
    changed = sorted(set(changed) | {p for p in layers.owner_changes(meta, new_meta) if p in after})
    cfg = json.loads(json.dumps(base['config']))
    cc = record['Config']
    image_cfg = cfg.setdefault('config', {})
    for key in ('Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'User', 'Labels', 'StopSignal', 'ExposedPorts'):
        if cc.get(key) not in (None, '', {}):
            image_cfg[key] = cc[key]
    image_cfg['Hostname'] = ''
    stage = Stage(0, None)
    stage.config = image_cfg
    builder = Builder.__new__(Builder)
    for change in a.change:
        for ins in parse_dockerfile(change):
            if ins.cmd in FS_INSTRUCTIONS or ins.cmd in ('FROM', 'ARG'):
                raise docker.Fail(f'{ins.cmd} is not a valid change for commit')
            getattr(builder, 'do_' + ins.cmd)(stage, ins, stage.scope())
    manifest = json.loads(json.dumps(base['manifest']))
    created = store_mod.now()
    command = ' '.join((cc.get('Entrypoint') or []) + (cc.get('Cmd') or []))
    history = {'created': created, 'created_by': command, 'comment': a.message}
    if a.author:
        cfg['author'] = a.author
        history['author'] = a.author
    work = st.tmpdir('commit')
    try:
        if changed or deleted:
            diff_id = layers.write_layer(root, changed, deleted, work / 'layer.tar', new_meta.get('modes'),
                                         new_meta.get('owners'))
            digest, size = layers.compress(st, work / 'layer.tar')
            manifest['layers'] = list(manifest.get('layers', [])) + [
                {'mediaType': images.OCI_LAYER_GZIP, 'digest': digest, 'size': size}]
            cfg.setdefault('rootfs', {'type': 'layers', 'diff_ids': []})['diff_ids'].append(diff_id)
        else:
            history['empty_layer'] = True
        cfg['created'] = created
        cfg['history'] = list(cfg.get('history', [])) + [history]
        cfg['config'] = stage.config
        config_bytes = json.dumps(cfg, separators=(',', ':')).encode()
        manifest['mediaType'] = images.OCI_MANIFEST
        manifest['config'] = {'mediaType': images.OCI_CONFIG, 'size': len(config_bytes),
                              'digest': 'sha256:' + hashlib.sha256(config_bytes).hexdigest()}
        # The new image's rootfs: the container's tree (a copy, the
        # container keeps its own).
        image_root = work / 'rootfs'
        if root is None:
            runspec.copy_rootfs(st.image_dir(record['Image']) / 'rootfs', image_root)
        else:
            runspec.copy_rootfs(root, image_root)
        image_id = install_built(st, config_bytes, manifest, image_root, new_meta)
    finally:
        store_mod.remove(work)
    if a.repository:
        tag_image(st, image_id, [a.repository])
    print('sha256:' + image_id)


def cmd_push(st, args):
    docker = cli()
    p = docker.parser('push', 'Upload an image to a registry')
    p.add_argument('-q', '--quiet', action='store_true')
    p.add_argument('-a', '--all-tags', action='store_true')
    p.add_argument('name')
    a = p.parse_args(args)
    ref = registry.Reference(a.name)
    image_id = st.resolve_image(a.name)
    info = st.image_info(image_id)
    manifest = info['manifest']
    client = registry.Client(ref, push=True)
    for layer in manifest['layers']:
        blob = st.blob(layer['digest'])
        if not blob.exists():
            raise StoreError(f'layer {layer["digest"]} is not in the local store; pull the base image again')
        uploaded = client.upload_blob(layer['digest'], blob)
        if not a.quiet:
            print(f'{layer["digest"][7:19]}: {"Pushed" if uploaded else "Layer already exists"}')
    config_path = st.image_dir(image_id) / 'config.json'
    client.upload_blob(manifest['config']['digest'], config_path)
    body = json.dumps(manifest, separators=(',', ':')).encode()
    client.put_manifest(ref.tag or ref.digest, body, manifest.get('mediaType', images.OCI_MANIFEST))
    digest = 'sha256:' + hashlib.sha256(body).hexdigest()
    print(f'{ref.tag}: digest: {digest} size: {len(body)}')
