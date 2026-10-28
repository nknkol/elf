#!/usr/bin/env python3
"""Validate an agent filesystem profile. Does not execute or enforce it."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath


class ProfileError(ValueError):
    pass


def fields(obj, allowed, required):
    if not isinstance(obj, dict) or set(obj) - allowed or required - set(obj):
        raise ProfileError(f'Expected fields {sorted(required)}; allowed {sorted(allowed)}')


def absolute(value):
    if not isinstance(value, str) or not value.startswith('/') or '\0' in value:
        raise ProfileError('Paths must be absolute strings without NUL')
    if '..' in value.split('/') or str(PurePosixPath(value)) != value or value.startswith('//'):
        raise ProfileError(f'Path must use canonical spelling: {value!r}')
    return value


def expand(value, variables):
    if not isinstance(value, str):
        raise ProfileError('Path must be a string')
    if value.startswith('${') and value.endswith('}'):
        key = value[2:-1]
        if key not in variables:
            raise ProfileError(f'Missing explicit path variable: {key}')
        value = variables[key]
    if '$' in value:
        raise ProfileError('Only whole-path ${BREW_PREFIX} and ${WORKSPACE} variables are supported')
    return absolute(value)


def contains(parent, child):
    return parent == '/' or parent == child or child.startswith(parent + '/')


def compile_profile(profile, *, brew_prefix, workspace, state):
    fields(profile, {'version', 'default', 'mounts', 'private'}, {'version', 'default', 'mounts', 'private'})
    if type(profile['version']) is not int or profile['version'] != 1 or profile['default'] != 'deny':
        raise ProfileError('Only version 1 with default=deny is supported')
    if not isinstance(profile['mounts'], list) or not isinstance(profile['private'], list):
        raise ProfileError('mounts and private must be arrays')
    variables = {'BREW_PREFIX': brew_prefix, 'WORKSPACE': workspace}
    state = str(Path(absolute(state)).resolve())
    mounts = []
    destinations = set()
    def add(source, target, access, kind):
        if target == '/' or target in destinations:
            raise ProfileError('Root exposure and duplicate destinations are disallowed in agent profiles')
        destinations.add(target)
        mounts.append(dict(source=source, target=target, access=access, kind=kind))
    for mount in profile['mounts']:
        fields(mount, {'source', 'target', 'access'}, {'source', 'access'})
        source = expand(mount['source'], variables)
        target = expand(mount.get('target', mount['source']), variables)
        if mount['access'] not in ('ro', 'rw'):
            raise ProfileError('Mount access must be ro or rw')
        try:
            host = str(Path(source).resolve(strict=True))
        except (OSError, RuntimeError) as exc:
            raise ProfileError(f'Cannot resolve source: {source}') from exc
        # Keep the source spelling as guest destination, important for brew symlinks.
        if contains(host, state) or contains(state, host):
            raise ProfileError('Private state must be separate from all exposed host trees')
        add(host, target, mount['access'], 'bind')
    for private in profile['private']:
        fields(private, {'name', 'target'}, {'name', 'target'})
        name = private['name']
        if name not in ('home', 'tmp', 'cache'):
            raise ProfileError('Private directory name must be home, tmp or cache')
        add(str(Path(state) / name), absolute(private['target']), 'rw', 'private')
    names = [p['name'] for p in profile['private']]
    if len(names) != len(set(names)):
        raise ProfileError('Private directory names must be unique')
    # Nested visibility is intentional: deepest component prefix wins.
    mounts.sort(key=lambda m: len(PurePosixPath(m['target']).parts), reverse=True)
    return dict(version=1, kind='agent-filesystem-plan', enforcement='not-connected',
                default='deny', state=state, mounts=mounts)


def access_for(plan, canonical_guest_path):
    """String policy model only, not authorization on a host filesystem.

    Runtime must account for symlinks, case aliases and retained mount identity;
    lowercase conversion is not a substitute for that resolution.
    """
    path = absolute(canonical_guest_path)
    for mount in plan['mounts']:
        if contains(mount['target'], path):
            return mount['access']
    return 'deny'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile', type=Path)
    parser.add_argument('--brew-prefix', required=True)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--state', required=True, help='Private backing directory, outside exposed trees')
    args = parser.parse_args()
    try:
        profile = json.loads(args.profile.read_text())
        plan = compile_profile(profile, brew_prefix=args.brew_prefix,
                               workspace=args.workspace, state=args.state)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(plan, indent=2))


if __name__ == '__main__':
    main()
