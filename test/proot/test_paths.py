#!/usr/bin/env python3
"""Real filesystem tests of the extracted canonicalizer; never uses ptrace."""
import errno
import os
from pathlib import Path
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

here = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='proot-path-', dir=lib.BUILD) as tmp:
    work = Path(tmp)
    binary = work / 'harness'
    subprocess.run([os.environ.get('CC', 'clang'), '-D_GNU_SOURCE', '-std=c11',
                    '-Wall', '-Wextra', '-Werror', '-I'+str(lib.REPO/'vendor/proot/src'),
                    *[str(lib.REPO/'vendor/proot/src/path'/name) for name in
                      ('canon_core.c', 'path_helpers.c', 'resolve_core.c', 'binding_core.c')],
                    str(here/'path_harness.c'), '-o', str(binary)], check=True)
    binding_test = work/'binding-test'
    subprocess.run([os.environ.get('CC', 'clang'), '-D_GNU_SOURCE', '-std=c11',
                    '-Wall', '-Wextra', '-Werror', '-I'+str(lib.REPO/'vendor/proot/src'),
                    str(lib.REPO/'vendor/proot/src/path/binding_core.c'),
                    str(lib.REPO/'vendor/proot/src/path/path_helpers.c'),
                    str(here/'test_bindings.c'), '-o', str(binding_test)], check=True)
    subprocess.run([str(binding_test)], check=True, timeout=10)
    root, bind = work/'root', work/'bind'
    for d in (root/'real/sub', root/'cwd', root/'mnt', root/'mnt-other',
              root/'old', root/'proc', bind):
        d.mkdir(parents=True, exist_ok=True)
    for f in (root/'real/file', root/'cwd/file', root/'mnt-other/file',
              root/'old/file', root/'plain', bind/'file'):
        f.write_text('fixture\n')
    (root/'link').symlink_to('real/sub')
    (root/'absolute').symlink_to('/real/file')
    (root/'relative').symlink_to('real/file')
    (root/'dangling').symlink_to('/missing')
    (root/'loop1').symlink_to('loop2')
    (root/'loop2').symlink_to('loop1')
    (root/'proc/link').symlink_to('/real/file')
    (bind/'absolute').symlink_to('/real/file')
    (bind/'relative').symlink_to('file')
    passed = 0

    def check(name, path, guest=None, *, follow=True, cwd='/', fd=None,
              rename=None, error=0, final=0, bound=False):
        global passed
        p = subprocess.run([str(binary), str(root), str(bind), cwd, path,
                            str(int(follow)), str(fd) if fd else '-',
                            str(rename) if rename else '-'],
                           text=True, capture_output=True, timeout=10, check=True)
        lines = p.stdout.splitlines()
        assert int(lines[0]) == error, (name, p.stdout, p.stderr)
        if error == 0:
            expected_host = str(bind)+guest[4:] if bound else str(root)+guest
            assert lines[1] == guest, (name, lines, guest)
            # join_paths preserves a trailing slash at a bind root.
            assert lines[2] == expected_host, (name, lines, expected_host)
            assert int(lines[3]) == final, (name, lines, final)
        passed += 1
        print('PASS:', name)

    check('absolute', '/real/file', '/real/file')
    check('cwd-relative', 'file', '/cwd/file', cwd='/cwd')
    check('dot and separators', '//real/./file', '/real/file')
    check('symlink BEFORE dotdot', '/link/../file', '/real/file')
    check('absolute symlink stays guest-rooted', '/absolute', '/real/file')
    check('relative symlink', '/relative', '/real/file')
    check('nofollow final symlink', '/absolute', '/absolute', follow=False)
    check('nofollow still follows intermediate links', '/link/../file', '/real/file', follow=False)
    check('bind', '/mnt/file', '/mnt/file', bound=True)
    check('bind prefix component boundary', '/mnt-other/file', '/mnt-other/file')
    check('absolute symlink inside bind', '/mnt/absolute', '/real/file')
    check('relative symlink inside bind', '/mnt/relative', '/mnt/file', bound=True)
    check('missing final deferred to syscall', '/new', '/new', final=-errno.ENOENT)
    check('dangling symlink final deferred', '/dangling', '/missing', final=-errno.ENOENT)
    check('missing intermediate', '/absent/file', error=-errno.ENOENT)
    check('non-directory intermediate', '/plain/file', error=-errno.ENOTDIR)
    check('trailing slash preserved', '/plain/', '/plain/', final=-errno.ENOTDIR)
    check('final dot preserved', '/real/.', '/real/.')
    check('root dotdot clamped', '/../../real/file', '/real/file')
    check('symlink loop', '/loop1', error=-errno.ELOOP)
    check('empty path rejected', '', error=-errno.ENOENT)
    check('non-directory fd rejected', 'file', fd=root/'plain', error=-errno.ENOTDIR)
    check('directory fd', 'file', '/real/file', fd=root/'real')
    check('bound directory fd', 'file', '/mnt/file', fd=bind, bound=True)
    check('directory fd after rename', 'file', '/renamed/file', fd=root/'old', rename=root/'renamed')
    check('absolute ignores non-directory fd', '/real/file', '/real/file', fd=root/'plain')
    check('proc emulation explicitly unsupported by fixture', '/proc/link', error=-errno.EOPNOTSUPP)
    check('oversized path rejected', '/'+('x'*4096), error=-errno.ENAMETOOLONG)
    print(f'{passed} filesystem semantic checks passed (no ptrace).')
