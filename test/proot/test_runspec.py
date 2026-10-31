#!/usr/bin/env python3
"""Container run options of the loader (docs/OCI.md, R1): --cwd, --user,
--hostname, many -e entries and volumes, and the exec helper's PATH lookup.

Expected: --cwd enters the guest directory through the binds (a missing one
is fatal before the program starts); --user sets every uid/gid and the only
supplementary group; --hostname is the uname nodename in the program and in
its exec'd children. Both builds, plain and with --isolate."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

GUEST = r'''
import json, os, subprocess, sys
out = {"cwd": os.getcwd(), "ids": [os.getresuid(), os.getresgid(), os.getgroups()],
       "node": os.uname().nodename, "envs": sum(k.startswith("ELF_T") for k in os.environ)}
out["child"] = subprocess.run([sys.argv[1], "-B", "-c",
                               "import os; print(os.uname().nodename, os.getuid(), os.getcwd())"],
                              capture_output=True, text=True).stdout.strip()
print("RESULT " + json.dumps(out))
'''

python = Path(sys.executable).resolve()
with tempfile.TemporaryDirectory(prefix='runspec-', dir=lib.BUILD) as tmp:
    work = Path(tmp, 'work')
    (work / 'sub').mkdir(parents=True)
    bindir = Path(tmp, 'bin')
    bindir.mkdir()
    (bindir / 'py').symlink_to(python)
    helper = Path(tmp, 'helper')
    shutil.copy2(lib.BUILD / 'elf-exec-helper', helper)
    # More volumes than the old limit of 16; the last ones matter.
    extra = []
    for i in range(30):
        Path(tmp, f'v{i}').mkdir()
        extra += ['-v', f'{tmp}/v{i}:/runspec-v{i}']
    envs = [arg for i in range(100) for arg in ('-e', f'ELF_T{i}=x')]
    for suffix, loader in lib.loaders():
        for isolate in ([], ['--isolate']):
            common = [str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container', '--root', '/',
                      '-v', f'{work}:/runspec', '-v', f'{bindir}:/runspec-bin', *extra]
            p = subprocess.run([*common, '--cwd', '/runspec/sub', '--user', '1000:1001',
                                '--hostname', 'box1', *envs, '-e', 'PATH=/runspec-bin',
                                '--', str(python).lstrip('/'), '-B', '-c', GUEST, str(python)],
                               cwd='/', capture_output=True, text=True, timeout=120)
            lines = [line for line in p.stdout.splitlines() if line.startswith('RESULT ')]
            assert p.returncode == 0 and lines, (suffix, isolate, p.returncode, p.stderr[-2000:])
            out = json.loads(lines[-1][7:])
            expected = {'cwd': '/runspec/sub', 'ids': [[1000] * 3, [1001] * 3, [1001]],
                        'node': 'box1', 'envs': 100, 'child': 'box1 1000 /runspec/sub'}
            assert out == expected, (suffix, isolate, out)
            # A missing working directory: an error, the program never runs.
            p = subprocess.run([*common, '--cwd', '/runspec/missing', '--', 'bin/true'],
                               cwd='/', capture_output=True, text=True, timeout=60)
            assert p.returncode == 1 and 'cannot enter working directory' in p.stderr, \
                (suffix, isolate, p.returncode, p.stderr)
            # The helper: a name without "/" is looked up in the guest PATH
            # (a symlink inside a volume); unknown names exit 127.
            p = subprocess.run([*common, '-e', 'PATH=/nonexistent:/runspec-bin', '--',
                                str(helper).lstrip('/'), '/runspec', 'py', 'py', '-B', '-c',
                                'import os; print(os.getcwd())'],
                               cwd='/', capture_output=True, text=True, timeout=60)
            assert p.returncode == 0 and p.stdout.strip() == '/runspec', \
                (suffix, isolate, p.returncode, p.stdout, p.stderr)
            p = subprocess.run([*common, '-e', 'PATH=/runspec-bin', '--', str(helper).lstrip('/'),
                                '/', 'no-such-command', 'no-such-command'],
                               cwd='/', capture_output=True, text=True, timeout=60)
            assert p.returncode == 127 and 'command not found' in p.stderr, \
                (suffix, isolate, p.returncode, p.stderr)
            print('PASS: --cwd, --user, --hostname, envs, volumes, helper PATH:',
                  loader.name, *isolate)
