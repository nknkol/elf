#!/usr/bin/env python3
"""Real notification callbacks with FD snapshots; not payload FD interception."""
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='fd-clone-') as temp:
    exe = Path(temp) / 'probe'
    native = Path(temp) / 'native-fp'
    subprocess.run(['clang', '-nostdlib', '-static', str(repo / 'test/fd_table/thread_fp.S'),
                    '-o', str(native)], check=True)
    subprocess.run([str(native)], check=True, timeout=5)
    files = ['test/fd_table/clone_fd_test.c', 'test/fd_table/clone_notify_probe.S',
             'src/payload/arch/aarch64/clone_entry.S', 'src/payload/logic/clone_notify.c',
             'src/payload/logic/fd_table.c', 'src/payload/logic/fd_clone.c',
             'src/payload/logic/fd_registry.c']
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror', '-Wl,-no-pie', '-DHOST_THREAD_FP_ZERO',
                    '-I' + str(repo / 'src/payload/include'),
                    *[str(repo / f) for f in files], '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=30)

    registry = Path(temp) / 'registry'
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/registry.c'),
                    *[str(repo / ('src/payload/logic/' + name + '.c'))
                      for name in ('fd_table', 'fd_clone', 'fd_registry')],
                    '-o', str(registry)], check=True)
    subprocess.run([str(registry)], check=True, timeout=10)

    guard_obj = Path(temp) / 'guard.o'
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector',
                    '-I' + str(repo / 'src/payload/include'), '-c',
                    str(repo / 'src/payload/logic/fd_guard.c'), '-o', str(guard_obj)], check=True)
    assert not subprocess.check_output(['llvm-nm', '--undefined-only', str(guard_obj)], text=True).strip()
    guard = Path(temp) / 'guard'
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/guard.c'), str(guard_obj),
                    *[str(repo / ('src/payload/logic/' + name + '.c'))
                      for name in ('fd_table', 'fd_clone', 'fd_registry')],
                    '-o', str(guard)], check=True)
    subprocess.run([str(guard)], check=True, timeout=20)
