#!/usr/bin/env python3
"""Native vs loader micro benchmarks (not part of make check; timing varies).

Configurations: native, default loader (PRoot path translation only) and the
FD experiment with --guard-file-access (full policy). Reports ns/op medians
of several runs and the overhead ratio against native.
"""
import argparse
import json
import statistics
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runs', type=int, default=5)
parser.add_argument('--json', type=Path, help='Also write results here')
args = parser.parse_args()

with tempfile.TemporaryDirectory(prefix='bench-', dir=build) as tmp:
    root = Path(tmp)
    work = root / 'work'
    (work / 'bench').mkdir(parents=True)
    (work / 'bench/file').write_bytes(bytes(range(256)) * 16)
    for index in range(62):
        (work / 'bench' / f'entry{index:02d}').write_bytes(b'')
    probe = root / 'bench'
    subprocess.run(['clang', '-O2', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', str(repo / 'test/bench/bench.c'), '-o', str(probe)],
                   check=True)
    configs = {
        'native': ([str(probe), str(work)], None),
        'default': ([str(build / 'elfloader-proot'), '--mode', 'container', '--root', str(root),
                     '-v', f'{work}:/work', '--', './bench', '/work'], root),
        'experiment': ([str(build / 'elfloader-proot-fd-experiment'), '--mode', 'container',
                        '--root', str(root), '-v', f'{work}:/work', '--', './bench', '/work'], root),
        'mutation': ([str(build / 'elfloader-proot-fd-experiment'), '--mode', 'container',
                      '--root', str(root), '-v', f'{work}:/work', '--guard-file-mutations', 'dw',
                      '--allow-stdio-output', '--', './bench', '/work'], root),
        'guarded': ([str(build / 'elfloader-proot-fd-experiment'), '--mode', 'container',
                     '--root', str(root), '-v', f'{work}:/work', '--guard-file-access', 'dw',
                     '--allow-stdio-output', '--', './bench', '/work'], root),
        # Default build with the opt-in seccomp backstop (filter on every call).
        'backstop': ([str(build / 'elfloader-proot'), '--mode', 'container', '--root', str(root),
                      '--seccomp-backstop', '-v', f'{work}:/work', '--', './bench', '/work'], root),
    }
    results = {}
    for name, (argv, cwd) in configs.items():
        runs = []
        for _ in range(args.runs):
            p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=600)
            assert p.returncode == 0, (name, p.returncode, p.stdout, p.stderr[-2000:])
            runs.append(dict(line.split() for line in p.stdout.splitlines()))
        results[name] = {case: statistics.median(int(r[case]) for r in runs) for case in runs[0]}
cases = list(results['native'])
print(f"{'case':<12}" + ''.join(f'{c:>12}' for c in results) + f"{'default/x':>11}{'guarded/x':>11}")
for case in cases:
    row = [results[c][case] for c in results]
    base = max(results['native'][case], 1)
    print(f'{case:<12}' + ''.join(f'{v:>12.0f}' for v in row) +
          f"{results['default'][case] / base:>11.1f}{results['guarded'][case] / base:>11.1f}")
if args.json:
    args.json.write_text(json.dumps(results, indent=2))
