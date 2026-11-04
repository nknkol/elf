#!/usr/bin/env python3
"""A Go program under the loader (goprobe/main.go, a static linux/arm64
binary committed next to its source; rebuild: in test/proot/goprobe,
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -buildvcs=false
-ldflags "-s -w" -o goprobe .). Go programs have their own svc
instructions, keep g in x28, run goroutines on stacks of a few KiB, block
one thread per goroutine in a call and vfork from goroutines (os/exec).

Expected, both builds, plain and with --isolate: 64 goroutines each make,
read, stat, list and remove 200 files; 200 goroutines blocked in open of
FIFOs at once all open; signals arrive while goroutines spin and allocate
(async preemption); 16 concurrent os/exec children answer; 32 loopback TCP
clients get their echo."""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

binary = Path(__file__).with_name('goprobe') / 'goprobe'
if not binary.exists():
    print('SKIP: goprobe binary missing:', binary)
    sys.exit(0)
with tempfile.TemporaryDirectory(prefix='go-', dir=lib.mode_capable()) as tmp:
    root = Path(tmp)
    shutil.copy(binary, root / 'goprobe')
    (root / 'goprobe').chmod(0o755)
    (root / 'work').mkdir()
    (root / 'dev').mkdir()
    (root / 'dev' / 'null').touch()
    for suffix, loader in lib.loaders():
        for isolate in ([], ['--isolate']):
            what = (loader.name, *isolate)
            p = subprocess.run([str(loader), *lib.ISOLATE_EXTRA, *isolate, '--mode', 'container',
                                '--root', str(root), '-v', '/dev/null:/dev/null', '--', './goprobe', '/work'],
                               cwd='/', capture_output=True, text=True, timeout=300)
            assert p.returncode == 0 and 'goprobe passed' in p.stdout, \
                (what, p.returncode, p.stdout[-1500:], p.stderr[-1500:])
            print('PASS: Go program (goroutine file calls, 200 blocked opens, signals and preemption,'
                  ' concurrent os/exec, loopback TCP):', *what)
