#!/usr/bin/env python3
"""Whole workloads: native against the loader, plain and with --isolate.

  python3 test/isolation/native_bench.py [--runs N] [--loader elfloader|elfloader-guarded] [--prefix DIR]

The programs are the host's own (harmonybrew: clang, make, git, python3,
node, coreutils, tar; the system sh), which run natively on HarmonyOS.
Executing a name does not require being able to look it up there: /bin/ls
(/system/bin) is a link whose lstat is refused while readlink works; the
loader tells such links by readlink, so it runs in every mode.
The loader's own TMPDIR is its glue base, where the broker serves only
proot-glue-* names: the guest's TMPDIR is set with -e instead. Under
the loader the host's / is the root, so every path is the same in all three
modes. Each workload writes only below a fresh directory on case-sensitive
storage (--work). The modes take turns in every run; the median wall time
of each is reported with its ratio to native, and stdout must be the same
in all modes. Not part of make check (timings vary)."""
import argparse
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('--runs', type=int, default=3)
parser.add_argument('--loader', default='elfloader')
parser.add_argument('--prefix', type=Path, default=Path.home() / '.harmonybrew',
                    help='where the native toolchain lives (bin/ with clang, make, git, python3, node)')
parser.add_argument('--work', type=Path, default=Path('/data/storage/el2/base/cache'))
args = parser.parse_args()
loader = lib.loader(args.loader[len('elfloader'):])
bin_dir = args.prefix / 'bin'
for tool in ('clang', 'make', 'git', 'python3', 'node'):
    if not (bin_dir / tool).exists():
        print(f'SKIP: {bin_dir / tool} missing')
        raise SystemExit(0)
pylib = next((args.prefix / 'lib').glob('python3.*'), None) or Path(subprocess.check_output(
    [str(bin_dir / 'python3'), '-c', 'import os; print(os.path.dirname(os.__file__))'], text=True).strip())

C_PROJECT = '''
mkdir proj && cd proj
for i in $(seq 1 16); do printf 'int f%d(int x){int s=0;for(int k=0;k<x;k++)s+=k*%d;return s;}\\n' $i $i > f$i.c; done
printf '#include <stdio.h>\\n' > main.c
for i in $(seq 1 16); do printf 'int f%d(int);\\n' $i >> main.c; done
printf 'int main(void){long s=0;' >> main.c
for i in $(seq 1 16); do printf 's+=f%d(10);' $i >> main.c; done
printf 'printf("%%ld\\\\n",s);return 0;}\\n' >> main.c
printf 'OBJ=$(patsubst %%.c,%%.o,$(wildcard *.c))\\nprog: $(OBJ)\\n\\tclang -o $@ $^\\n%%.o: %%.c\\n\\tclang -O1 -c $<\\n' > Makefile
make -s -j4 && ./prog
'''

WORKLOADS = {
    'clang+make (17 files, -j4)': C_PROJECT,
    'git init/add/commit/log': '''
mkdir repo && cd repo && git init -q && git config user.email t@t && git config user.name t
for i in $(seq 1 200); do echo "line $i" > file$i.txt; done
git add -A && git commit -qm first && echo change >> file7.txt && git commit -qam second
git log --oneline | wc -l; git status --short | wc -l; git ls-files | wc -l
''',
    'python stdlib imports': '''
python3 -c "import json, email, http.client, asyncio, sqlite3, decimal, xml.dom.minidom, unittest; print('ok')"
''',
    'python venv + pip --version': '''
python3 -m venv venv && ./venv/bin/python -c "import sys; print(sys.prefix != sys.base_prefix)"
./venv/bin/pip --version >/dev/null && echo pip-ok
''',
    'node fs + npm --version': '''
node -e "const fs=require('fs'); console.log(fs.readdirSync('.').length >= 0)"
npm --version >/dev/null && echo npm-ok
''',
    'tar czf python stdlib': f'''
tar czf py.tgz -C {pylib} . && tar tzf py.tgz | wc -l
''',
    'du -a python stdlib': f'''
du -a {pylib} | wc -l
''',
    'shell: 500 files write/read': '''
mkdir many && cd many && for i in $(seq 1 500); do echo $i > f$i; done; cat f* | wc -l; ls | wc -l
''',
}

env = {'PATH': f'{bin_dir}:/bin:/system/bin', 'LANG': 'C.UTF-8'}


def run(script, mode, base):
    work = Path(tempfile.mkdtemp(prefix='nb-', dir=base))
    # The guest's HOME and TMPDIR; the loader's own TMPDIR names its glue
    # base, which the broker opens only for proot-glue-* names.
    run_env = dict(env, HOME=str(work), TMPDIR=str(work))
    command = ['sh', '-c', f'set -e; cd {work}; ' + script]
    if mode == 'native':
        argv, cwd = ['/bin/sh', *command[1:]], str(work)
    else:
        argv = [str(loader), *(['--isolate'] if mode == 'isolate' else []), '--mode', 'container', '--root', '/']
        for key, value in run_env.items():
            argv += ['-e', f'{key}={value}']
        argv, cwd = [*argv, '--', './bin/sh', *command[1:]], '/'
    start = time.monotonic()
    p = subprocess.run(argv, cwd=cwd, env=run_env if mode == 'native' else env, capture_output=True, text=True, timeout=1800,
                       stdin=subprocess.DEVNULL)
    elapsed = time.monotonic() - start
    shutil.rmtree(work, ignore_errors=True)
    return p, elapsed


MODES = ('native', 'plain', 'isolate')
failures = 0
print(f'loader {loader.name}, {args.runs} runs, load {os.getloadavg()[0]:.1f}')
print(f"{'workload':<30}{'native s':>10}{'plain s':>10}{'isolate s':>11}{'plain/n':>9}{'isolate/n':>11}  result")
totals = {m: 0.0 for m in MODES}
with tempfile.TemporaryDirectory(prefix='native-bench-', dir=args.work) as tmp:
    for name, script in WORKLOADS.items():
        times = {m: [] for m in MODES}
        outputs = {}
        problem = ''
        for _ in range(args.runs):
            for mode in MODES:
                p, elapsed = run(script, mode, tmp)
                if p.returncode and not problem:
                    problem = f'{mode} rc={p.returncode}: {p.stderr.strip()[-300:]}'
                outputs.setdefault(mode, p.stdout)
                times[mode].append(elapsed)
        if not problem:
            differ = [m for m in MODES if outputs[m] != outputs['native']]
            if differ:
                problem = f'output of {differ} differs: {outputs["native"]!r} vs {outputs[differ[0]]!r}'
        median = {m: statistics.median(times[m]) for m in MODES}
        for m in MODES:
            totals[m] += median[m]
        print(f'{name:<30}{median["native"]:>10.2f}{median["plain"]:>10.2f}{median["isolate"]:>11.2f}'
              f'{median["plain"] / median["native"]:>9.2f}{median["isolate"] / median["native"]:>11.2f}  '
              f'{"FAIL " + problem if problem else "same output"}', flush=True)
        failures += bool(problem)
print(f'{"total":<30}{totals["native"]:>10.2f}{totals["plain"]:>10.2f}{totals["isolate"]:>11.2f}'
      f'{totals["plain"] / totals["native"]:>9.2f}{totals["isolate"] / totals["native"]:>11.2f}')
raise SystemExit(1 if failures else 0)
