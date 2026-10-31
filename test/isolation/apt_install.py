#!/usr/bin/env python3
"""apt with and without --isolate (docs/ISOLATION_TESTING.md, goal N).

  python3 test/isolation/apt_install.py UBUNTU_ARCHIVE [--work DIR] [--loader elfloader|elfloader-guarded]

Each mode gets a fresh Ubuntu base root extracted on case-sensitive storage
(--work), then runs apt-get update, installs two small packages, runs them,
removes one and lists the installed packages. Both modes must succeed with
the same output. Needs the network; not part of make check. Wall times
follow the mirror: when it drops a connection apt retries with a delay and
spins on stat meanwhile (in both modes), so compare outputs, not times."""
import argparse
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

spec = importlib.util.spec_from_file_location('rootfs_extract', lib.REPO / 'test/alpine/run.py')
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)

parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument('archive', type=Path)
parser.add_argument('--work', type=Path, default=Path('/data/storage/el2/base/cache'))
parser.add_argument('--loader', default='elfloader')
args = parser.parse_args()
loader = lib.loader(args.loader[len('elfloader'):])

SCRIPT = '''
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
apt-get -qq install -y --no-install-recommends tree jq >/dev/null
tree --version | cut -d' ' -f1-2
echo '{"a":[1,2,3]}' | jq -c '.a | add'
mkdir -p /tmp/t/a/b && touch /tmp/t/a/b/c && tree --noreport /tmp/t
apt-get -qq remove -y jq >/dev/null
test -e /usr/bin/jq || echo jq-removed
dpkg-query -W -f '${Package} ${Status}\\n' tree jq libjq1 | sort
'''

results = {}
with tempfile.TemporaryDirectory(prefix='apt-iso-', dir=args.work) as tmp:
    for isolate in (False, True):
        root = Path(tmp) / ('isolate' if isolate else 'plain')
        root.mkdir()
        extract.extract_root(args.archive, root, materialize_hardlinks=True)
        shutil.copy2('/etc/resolv.conf', root / 'etc/resolv.conf')
        argv = [str(loader), *(['--isolate'] if isolate else []), '--mode', 'container', '--root', str(root),
                '--link-copy', '-v', '/dev/null:/dev/null', '-v', '/proc:/proc',
                '-e', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin', '-e', 'HOME=/root',
                '--', './usr/bin/sh', '-c', 'set -e;' + SCRIPT]
        start = time.monotonic()
        p = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=1800,
                           stdin=subprocess.DEVNULL)
        results[isolate] = (p, time.monotonic() - start)
        print(f'{"isolate" if isolate else "plain":<8} rc={p.returncode} {results[isolate][1]:.1f}s', flush=True)
        if p.returncode:
            print(p.stdout[-1500:], p.stderr[-1500:], sep='\n')

plain, isolated = results[False][0], results[True][0]
same = not plain.returncode and not isolated.returncode and plain.stdout == isolated.stdout
print(plain.stdout)
print('PASS: same output' if same else f'FAIL: outputs differ\n{isolated.stdout}')
raise SystemExit(0 if same else 1)
