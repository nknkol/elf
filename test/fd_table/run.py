#!/usr/bin/env python3
"""Standalone FD metadata core plus native kernel lifecycle comparisons.
This does not test interception: the core is not yet wired into the payload.
"""
import subprocess
import tempfile
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='fd-table-') as temp:
    obj = Path(temp) / 'fd_table.o'
    exe = Path(temp) / 'check'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                    '-I' + str(repo / 'src/payload/include'), '-c',
                    str(repo / 'src/payload/logic/fd_table.c'), '-o', str(obj)], check=True)
    undefined = subprocess.check_output(['llvm-nm', '--undefined-only', str(obj)], text=True)
    assert not undefined.strip(), undefined
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/check.c'), str(obj), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=20)
    snapshot_obj = Path(temp) / 'fd_snapshot.o'
    snapshot_exe = Path(temp) / 'snapshot'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                    '-I' + str(repo / 'src/payload/include'), '-c',
                    str(repo / 'src/payload/logic/fd_snapshot.c'), '-o', str(snapshot_obj)], check=True)
    undefined = subprocess.check_output(['llvm-nm', '--undefined-only', str(snapshot_obj)], text=True)
    assert not undefined.strip(), undefined
    handoff_obj = Path(temp) / 'fd_handoff.o'
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                    '-I' + str(repo / 'src/payload/include'), '-c',
                    str(repo / 'src/payload/logic/fd_handoff.c'), '-o', str(handoff_obj)], check=True)
    subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/snapshot.c'), str(obj), str(snapshot_obj), str(handoff_obj),
                    '-o', str(snapshot_exe)], check=True)
    subprocess.run([str(snapshot_exe)], check=True, timeout=20)

    close_exe = Path(temp) / 'close-commit'
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/close_commit.c'), str(obj),
                    '-o', str(close_exe)], check=True)
    subprocess.run([str(close_exe)], check=True, timeout=15)

    queue_exe = Path(temp) / 'close-queue'
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/close_queue.c'), str(obj),
                    *[str(repo / ('src/payload/logic/' + name + '.c'))
                      for name in ('fd_clone', 'fd_registry', 'fd_guard', 'fd_close_queue')],
                    '-o', str(queue_exe)], check=True)
    subprocess.run([str(queue_exe)], check=True, timeout=15)

    exec_exe = Path(temp) / 'close-exec'
    subprocess.run(['clang', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_table/close_exec.c'), str(obj),
                    *[str(repo / ('src/payload/logic/' + name + '.c'))
                      for name in ('fd_clone', 'fd_registry', 'fd_guard', 'fd_close_queue', 'fd_close_exec')],
                    '-o', str(exec_exe)], check=True)
    subprocess.run([str(exec_exe)], check=True, timeout=15)
