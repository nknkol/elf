#!/usr/bin/env python3
"""Probe ASCII case lookup and hardlinks inside explicitly selected directories.

Creates and removes a private temporary subdirectory per target. Observations
apply to that directory and current credentials, not an entire mount or policy.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import shutil
import tempfile


def failure(error):
    return dict(errno=error.errno, message=str(error))


def case_lookup(directory):
    upper, lower = directory / 'CaseProbe', directory / 'caseprobe'
    upper.write_bytes(b'UPPER')
    try:
        with lower.open('xb') as stream:
            stream.write(b'lower')
    except FileExistsError:
        if lower.read_bytes() == b'UPPER':
            return dict(status='insensitive', scope='ASCII case pair only')
        return dict(status='inconsistent', scope='ASCII case pair only')
    if upper.read_bytes() == b'UPPER' and lower.read_bytes() == b'lower':
        return dict(status='sensitive', scope='ASCII case pair only')
    return dict(status='inconsistent', scope='ASCII case pair only')


def hardlinks(directory):
    source, target = directory / 'hard-source', directory / 'hard-target'
    source.write_bytes(b'before')
    try:
        os.link(source, target)
    except OSError as error:
        status = ('denied' if error.errno in (errno.EPERM, errno.EACCES) else
                  'unsupported' if error.errno in (errno.ENOSYS, errno.EOPNOTSUPP) else 'unknown')
        return dict(status=status, **failure(error))
    source.write_bytes(b'after')
    shared = source.samefile(target) and target.read_bytes() == b'after'
    links = source.stat().st_nlink
    return dict(status='supported' if shared and links >= 2 else 'inconsistent',
                shared_identity_and_content=shared, link_count=links)


def probe_directory(path):
    result = dict(requested=os.fspath(path), directory=None,
                  case_lookup=dict(status='unknown'), hardlinks=dict(status='unknown'),
                  cleanup=dict(status='not-created'))
    scratch = None
    try:
        directory = Path(path).resolve(strict=True)
        if not directory.is_dir():
            raise NotADirectoryError(errno.ENOTDIR, 'Probe target must be an existing directory', str(directory))
        result['directory'] = str(directory)
        scratch = Path(tempfile.mkdtemp(prefix='.elf-storage-probe-', dir=directory))
        for key, probe in (('case_lookup', case_lookup), ('hardlinks', hardlinks)):
            try:
                result[key] = probe(scratch)
            except OSError as error:
                result[key] = dict(status='unknown', **failure(error))
    except OSError as error:
        result['error'] = failure(error)
    finally:
        if scratch is not None:
            try:
                shutil.rmtree(scratch)
                result['cleanup'] = dict(status='removed')
            except OSError as error:
                result['cleanup'] = dict(status='failed', remaining_path=str(scratch), **failure(error))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directories', type=Path, nargs='+', help='Existing backing directories; writes temporary probe files')
    args = parser.parse_args()
    results = [probe_directory(path) for path in args.directories]
    print(json.dumps(dict(version=1, kind='storage-observations', enforcement='not-connected',
                          results=results), indent=2, ensure_ascii=False))
    # Denial of hardlinks is a measured capability, not failure to run the probe.
    return int(any('error' in result or result['cleanup']['status'] == 'failed' or
                   any(result[key]['status'] in ('unknown', 'inconsistent')
                       for key in ('case_lookup', 'hardlinks')) for result in results))


if __name__ == '__main__':
    raise SystemExit(main())
