#!/usr/bin/env python3
"""Launch a command under an agent profile with the experimental file access guard.

Compiles the profile with plan.py, prepares private state and a minimal
mountpoint-only root, then runs the FD-experiment loader with every mount's
deny/ro/rw access, a clean environment and a static exec helper. The helper
execs the guest command through the payload, so target, shebang and dynamic
linker resolution follow the same policy as later guest execs.

This enforces the documented file access mode of the experimental backend;
it is not a complete hostile-agent isolation guarantee (see docs/STATUS.md).
"""
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path, PurePosixPath
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'test'))
import lib  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BUILD = lib.BUILD
spec = importlib.util.spec_from_file_location('agent_plan', HERE / 'plan.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)
ProfileError = plan.ProfileError

MAX_BINDS = 16  # CONFIG_MAX_BINDS in src/payload/include/config.h
MAX_ENVS = 16   # CONFIG_MAX_ENVS
MAX_VALUE = 255  # CONFIG_MAX_PATH including NUL
MARKER = '.elf-skeleton'
HELPER = '.elf-exec'


def verified_backend(loader):
    """Use only a loader/helper pair recorded by the same build manifest."""
    manifest = json.loads((loader.parent / 'elfloader-guarded.json').read_text())
    helper = loader.parent / 'elf-exec-helper'
    for path, key in ((loader, 'sha256'), (helper, 'exec_helper_sha256')):
        if hashlib.sha256(path.read_bytes()).hexdigest() != manifest.get(key):
            raise ProfileError(f'{path} does not match the FD experiment build manifest')
    return helper


def environment(compiled, extra, term):
    """Clean guest environment; host variables are never inherited."""
    targets = {m['kind'] + ':' + Path(m['source']).name: m['target'] for m in compiled['mounts']}
    home = targets.get('private:home', '/')
    path = ['/usr/local/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin']
    for mount in compiled['mounts']:
        if mount['kind'] == 'bind' and mount['access'] == 'ro':
            for name in ('bin', 'sbin'):
                if Path(mount['source'], name).is_dir():
                    path.insert(0, str(PurePosixPath(mount['target'], name)))
    env = {'HOME': home, 'PATH': ':'.join(dict.fromkeys(path)), 'USER': 'agent',
           'LOGNAME': 'agent', 'SHELL': '/bin/sh', 'LANG': 'C.UTF-8'}
    if 'private:tmp' in targets:
        env['TMPDIR'] = targets['private:tmp']
    if 'private:cache' in targets:
        env['XDG_CACHE_HOME'] = targets['private:cache']
    if term:
        env['TERM'] = term
    for item in extra:
        key, sep, value = item.partition('=')
        if not sep or not key or '\0' in item:
            raise ProfileError(f'Environment entries must be KEY=VALUE: {item!r}')
        env[key] = value
    entries = [f'{key}={value}' for key, value in env.items()]
    if len(entries) > MAX_ENVS:
        raise ProfileError(f'Backend supports at most {MAX_ENVS} environment entries')
    for entry in entries:
        if len(entry.encode()) > MAX_VALUE:
            raise ProfileError(f'Environment entry exceeds {MAX_VALUE} bytes: {entry[:40]}...')
    return entries


def prepare_state(compiled):
    """Create private directories and a root holding only mountpoints.

    The root is the denied mount: guests can traverse its directories to reach
    exposed mounts, list exactly those names, and stat only these placeholders.
    """
    state = Path(compiled['state'])
    for mount in compiled['mounts']:
        if mount['kind'] == 'private':
            Path(mount['source']).mkdir(mode=0o700, parents=True, exist_ok=True)
    root = state / 'root'
    if root.exists():
        if not (root / MARKER).is_file():
            raise ProfileError(f'{root} exists and was not created by this launcher')
        shutil.rmtree(root)
    root.mkdir(mode=0o755, parents=True)
    (root / MARKER).write_text('mountpoint skeleton; recreated on every launch\n')
    for mount in compiled['mounts']:
        node = root / mount['target'].lstrip('/')
        node.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if Path(mount['source']).is_dir():
            node.mkdir(mode=0o755, exist_ok=True)
        else:
            node.touch(mode=0o644, exist_ok=True)
    return root


def command_line(compiled, root, loader, workdir, command, env):
    if len(compiled['mounts']) > MAX_BINDS:
        raise ProfileError(f'Backend supports at most {MAX_BINDS} mounts; profile has '
                           f'{len(compiled["mounts"])}')
    for value in (str(root), workdir, *(m['source'] for m in compiled['mounts']),
                  *(m['target'] for m in compiled['mounts'])):
        if len(value.encode()) > MAX_VALUE:
            raise ProfileError(f'Path exceeds backend limit of {MAX_VALUE} bytes: {value}')
    if not command or not command[0].startswith('/'):
        raise ProfileError('Command must start with an absolute guest path')
    argv = [str(loader), '--mode', 'container', '--root', str(root)]
    vector = 'd'
    for mount in compiled['mounts']:
        if ':' in mount['source'] or ':' in mount['target']:
            raise ProfileError('Mount paths cannot contain ":" for the loader volume syntax')
        argv += ['-v', f'{mount["source"]}:{mount["target"]}']
        vector += 'r' if mount['access'] == 'ro' else 'w'
    argv += ['--guard-file-access', vector, '--allow-stdio-output', '--allow-pipe-output',
             '--allow-local-output', '--allow-stream-input', '--revalidate-file-fds']
    for entry in env:
        argv += ['-e', entry]
    return argv + ['--', f'./{HELPER}', workdir, command[0], *command]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('profile', type=Path)
    parser.add_argument('--brew-prefix', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--state', required=True, help='Private backing directory, outside exposed trees')
    parser.add_argument('--loader', type=Path, default=BUILD / 'elfloader-guarded')
    parser.add_argument('--cwd', help='Guest working directory (default: /workspace target)')
    parser.add_argument('--env', action='append', default=[], metavar='KEY=VALUE')
    parser.add_argument('--print', action='store_true', help='Print the launch as JSON instead of running it')
    parser.usage = '%(prog)s profile [options] -- /guest/command [args...]'
    # The guest command follows an explicit "--" so its options never reach argparse.
    argv = sys.argv[1:]
    if '--' not in argv:
        parser.error('separate the guest command with --')
    split = argv.index('--')
    args = parser.parse_args(argv[:split])
    command = argv[split + 1:]
    try:
        profile = json.loads(args.profile.read_text())
        compiled = plan.compile_profile(profile, brew_prefix=args.brew_prefix,
                                        workspace=args.workspace, state=args.state)
        workspace = next((m['target'] for m in compiled['mounts']
                          if m['kind'] == 'bind' and m['access'] == 'rw'
                          and Path(m['source']) == Path(args.workspace).resolve()), '/')
        workdir = plan.absolute(args.cwd or workspace)
        env = environment(compiled, args.env, os.environ.get('TERM'))
        loader = args.loader.resolve()
        helper = verified_backend(loader)
        if args.print:
            root = Path(compiled['state']) / 'root'
            argv = command_line(compiled, root, loader, workdir, command, env)
            print(json.dumps(dict(compiled, enforcement='experimental-file-access-guard',
                                  argv=argv), indent=2))
            return
        root = prepare_state(compiled)
        argv = command_line(compiled, root, loader, workdir, command, env)
        shutil.copy2(helper, root / HELPER)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    # The loader enters the root itself; the helper path is relative to it.
    os.chdir(root)
    sys.stdout.flush()
    os.execv(argv[0], argv)


if __name__ == '__main__':
    main()
