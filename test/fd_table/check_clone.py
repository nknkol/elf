#!/usr/bin/env python3
"""Native vs ELF-intercepted clone FD/VM sharing matrix, including a thread."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--strict-linux', action='store_true', help='Fail on native clone sharing deviations too')
args = parser.parse_args()

repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
loader = lib.loader()
modes = ['copy VM / copy FDs', 'copy VM / share FDs', 'share VM / copy FDs',
         'share VM / share FDs', 'thread / share FDs', 'thread / copy FDs']
results = []
deviations = []
with tempfile.TemporaryDirectory(prefix='clone-fds-', dir=build) as temp:
    probe = Path(temp) / 'probe'
    subprocess.run(['clang', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-O1', '-Wl,-e,_start',
                    str(repo / 'test/fd_table/clone_probe.c'),
                    str(repo / 'test/fd_table/clone_start.S'), '-o', str(probe)], check=True)
    for mode, name in enumerate(modes):
        outputs = []
        for backend in ['native', 'loader']:
            cmd = [str(probe), str(mode)]
            if backend == 'loader':
                cmd = [str(loader), '--mode', 'compat', '--'] + cmd
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            result = dict(mode=name, backend=backend, returncode=p.returncode,
                          stdout=p.stdout, stderr=p.stderr)
            results.append(result)
            (build / 'clone-fd-results.json').write_text(json.dumps(results, indent=2) + '\n')
            assert p.returncode == 0 and 'CLONE_OBSERVED\n' in p.stdout, result
            shared = 'CLOSED=-9\n' in p.stdout
            expected_shared = mode in (1, 3, 4)
            if shared != expected_shared:
                assert (mode in (1, 3) and not shared) or (mode == 5 and shared), result
                deviations.append(dict(mode=name, backend=backend,
                                       deviation='FD sharing differs from CLONE_FILES before child exit'))
                result['linux_conformance'] = False
            else:
                result['linux_conformance'] = True
            (build / 'clone-fd-results.json').write_text(json.dumps(results, indent=2) + '\n')
            outputs.append(p.stdout)
            print('HOST DEVIATION:' if not result['linux_conformance'] else 'PASS:', backend, name, flush=True)
        assert outputs[0] == outputs[1], results[-2:]
print('PASS: 6 native/loader comparisons; host deviations:', len(deviations) // 2)
print('FD metadata interception is not enabled; deviations are not conformance passes.')
if args.strict_linux and deviations:
    raise SystemExit('FAIL: native CLONE_FILES semantics differ in ' + str(len(deviations) // 2) + ' scenarios')
