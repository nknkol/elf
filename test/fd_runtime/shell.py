#!/usr/bin/env python3
"""Real rootfs shell workflows; report vfork rejection separately from passes."""
import subprocess
from pathlib import Path

build = Path(__file__).resolve().parents[2] / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
for directory, shell, prefix, cat in (
        ('alpine-test-root', './bin/busybox', ['sh'], '/bin/busybox cat'),
        ('ubuntu-root', './usr/bin/dash', [], '/usr/bin/cat')):
    root = build / directory
    if not (root / shell).exists():
        print('SKIP: optional shell workflows', directory)
        continue

    def run(command):
        return subprocess.run(
            [str(loader), '--mode', 'container', '--root', str(root),
             '-v', '/dev/null:/dev/null', '--', shell, *prefix, '-c', command],
            cwd=root, capture_output=True, text=True, timeout=20)

    cases = [
        ('pipeline-exec', f'printf payload | {cat}; printf "\\ndone\\n"', 'payload\ndone\n'),
        ('subshell', '(printf child); printf "parent\\n"', 'childparent\n'),
        ('background-wait', '(exit 7) & p=$!; wait "$p"; r=$?; printf "status=%s\\n" "$r"', 'status=7\n'),
        ('command-substitution', 'value=$(printf child); printf "value=%s\\n" "$value"', 'value=child\n'),
        ('redirect-fork', '(printf child >&3) 3>&1; printf "parent\\n"', 'childparent\n'),
    ]
    for name, command, expected in cases:
        p = run(command)
        assert (p.returncode, p.stdout) == (0, expected), (directory, name, p.returncode, p.stdout, p.stderr)
        print('PASS: shell workflow', directory, name)

    # A following builtin prevents tail-exec optimization. Ubuntu dash uses
    # vfork here; do not count a known failure as working shell compatibility.
    p = run(f'{cat} /dev/null; printf "done\\n"')
    if directory == 'ubuntu-root':
        assert p.returncode == 2 and not p.stdout and 'Cannot fork' in p.stderr, (p.returncode, p.stdout, p.stderr)
        print('KNOWN LIMIT: Ubuntu dash external command requires unsupported vfork')
    else:
        assert (p.returncode, p.stdout) == (0, 'done\n'), (p.returncode, p.stdout, p.stderr)
        print('PASS: shell workflow', directory, 'external-command')
