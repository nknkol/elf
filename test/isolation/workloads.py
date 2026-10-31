#!/usr/bin/env python3
"""Real workloads with and without --isolate (docs/ISOLATION_TESTING.md, goal N).

  python3 test/isolation/workloads.py ROOTFS [--runs N] [--loader elfloader|elfloader-guarded]

ROOTFS is an Ubuntu rootfs with gcc, make, git, python3, node and npm (on the
HarmonyOS device: /data/storage/el2/base/files/apt-root, case-sensitive
storage). The rootfs is not modified: every workload writes only below /w, a
fresh bound directory. Each workload runs under the loader without and with
--isolate; the outputs must be identical, and the median wall time of each
is reported with the ratio. Not part of make check (timings vary)."""
import argparse
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
parser.add_argument('rootfs', type=Path)
parser.add_argument('--runs', type=int, default=3)
parser.add_argument('--loader', default='elfloader')
parser.add_argument('--work', type=Path, default=Path('/data/storage/el2/base/cache'),
                    help='where the scratch /w directories are made (case-sensitive storage)')
args = parser.parse_args()
loader = lib.loader(args.loader[len('elfloader'):])

C_FILES = '''
mkdir -p proj && cd proj
for i in 1 2 3 4 5 6 7 8; do printf 'int f%d(int x){return x*%d;}\\n' $i $i > f$i.c; done
printf '#include <stdio.h>\\n' > main.c
for i in 1 2 3 4 5 6 7 8; do printf 'int f%d(int);\\n' $i >> main.c; done
printf 'int main(void){int s=0;' >> main.c
for i in 1 2 3 4 5 6 7 8; do printf 's+=f%d(1);' $i >> main.c; done
printf 'printf("%%d\\\\n",s);return 0;}\\n' >> main.c
printf 'OBJ=$(patsubst %%.c,%%.o,$(wildcard *.c))\\nprog: $(OBJ)\\n\\tcc -o $@ $^\\n%%.o: %%.c\\n\\tcc -O1 -c $<\\n' > Makefile
make -s -j4 && ./prog
'''

WORKLOADS = {
    'gcc+make (9 files, -j4)': C_FILES,
    'git init/add/commit/log': '''
mkdir repo && cd repo && git init -q && git config user.email t@t && git config user.name t
for i in $(seq 1 200); do echo "line $i" > file$i.txt; done
git add -A && git commit -qm first && echo change >> file7.txt && git commit -qam second
git log --oneline | wc -l; git status --short | wc -l; git ls-files | wc -l
''',
    'python stdlib imports': '''
python3 -c "import json, email, http.client, asyncio, sqlite3, decimal, xml.dom.minidom, unittest; print('ok')"
''',
    'python venv + pip list': '''
python3 -m venv /w/venv && /w/venv/bin/python -c "import sys; print(sys.prefix)"
/w/venv/bin/pip list --disable-pip-version-check 2>/dev/null | wc -l
''',
    'node + npm': '''
node -e "const fs=require('fs'); console.log(fs.readdirSync('/usr/lib').length > 0)"
npm --version >/dev/null && echo npm-ok
''',
    'tar czf /usr/include': '''
tar czf /w/inc.tgz -C /usr include && tar tzf /w/inc.tgz | wc -l
''',
    'find + stat (python lib)': '''
find /usr/lib/python3* -name '*.py' | wc -l
''',
    'dpkg-query': '''
dpkg-query -W | wc -l
''',
}


def run(script, isolate, base):
    work = Path(tempfile.mkdtemp(prefix='wl-', dir=base))
    argv = [str(loader), *(['--isolate'] if isolate else []), '--mode', 'container',
            '--root', str(args.rootfs), '--link-copy', '-v', f'{work}:/w',
            '-v', '/dev/null:/dev/null', '-v', '/proc:/proc',
            '-e', 'PATH=/usr/local/bin:/usr/bin:/bin', '-e', 'HOME=/w', '-e', 'LANG=C.UTF-8',
            '--', './usr/bin/sh', '-c', 'set -e; cd /w; ' + script]
    start = time.monotonic()
    p = subprocess.run(argv, cwd=args.rootfs, capture_output=True, text=True, timeout=900,
                       stdin=subprocess.DEVNULL)
    elapsed = time.monotonic() - start
    shutil.rmtree(work, ignore_errors=True)
    return p, elapsed


failures = 0
print(f"{'workload':<28}{'plain s':>10}{'isolate s':>11}{'ratio':>8}  result")
with tempfile.TemporaryDirectory(prefix='workloads-', dir=args.work) as tmp:
    for name, script in WORKLOADS.items():
        times = {False: [], True: []}
        outputs = {}
        problem = ''
        for _ in range(args.runs):
            for isolate in (False, True):
                p, elapsed = run(script, isolate, tmp)
                if p.returncode:
                    problem = f'{"isolate" if isolate else "plain"} rc={p.returncode}: {p.stderr.strip()[-300:]}'
                outputs.setdefault(isolate, p.stdout)
                times[isolate].append(elapsed)
        if not problem and outputs[False] != outputs[True]:
            problem = f'outputs differ: {outputs[False]!r} vs {outputs[True]!r}'
        plain, isolated = statistics.median(times[False]), statistics.median(times[True])
        print(f'{name:<28}{plain:>10.2f}{isolated:>11.2f}{isolated / plain:>8.2f}  '
              f'{"FAIL " + problem if problem else "same output"}', flush=True)
        failures += bool(problem)
raise SystemExit(1 if failures else 0)
