#!/usr/bin/env python3
"""End-to-end FD experiment through the built loader, not linked model callbacks."""
import struct
import errno
import array
import ctypes
import fcntl
import os
import socket
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
loader = build / 'elfloader-proot-fd-experiment'
assert hashlib.sha256(loader.read_bytes()).hexdigest() == json.loads(
    (build / 'elf-build-fd-experiment.json').read_text())['sha256']
# Compare status flags against this host: it may inherit O_NONBLOCK on accept.
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
accept_nonblock = 0
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_NONBLOCK |
                   socket.SOCK_CLOEXEC) as listener:
    listener.bind('')
    listener.listen(4)
    for mode in range(3):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(listener.getsockname())
            flags = socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK if mode == 1 else 0
            accepted = libc.syscall(202 if mode == 0 else 242,
                                    listener.fileno(), 0, 0, flags)
            assert accepted >= 0, ('native accept', mode, ctypes.get_errno())
            try:
                assert fcntl.fcntl(accepted, fcntl.F_GETFD) == (fcntl.FD_CLOEXEC if mode == 1 else 0)
                if fcntl.fcntl(accepted, fcntl.F_GETFL) & os.O_NONBLOCK:
                    accept_nonblock |= 1 << mode
            finally:
                os.close(accepted)
print('Native accept/accept4 nonblocking mask:', accept_nonblock)
# Some hosts deliver rights only on the first peek; record native behavior.
peek_rights = 0
sender, receiver = socket.socketpair()
try:
    sender.sendmsg([b'R'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                            array.array('i', [sender.fileno(), sender.fileno()]))])
    for mode, flags in enumerate((socket.MSG_PEEK, socket.MSG_PEEK, socket.MSG_CMSG_CLOEXEC)):
        data, ancillary, _, _ = receiver.recvmsg(1, socket.CMSG_SPACE(8), flags)
        assert data == b'R'
        for level, kind, raw in ancillary:
            assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
            received = array.array('i'); received.frombytes(raw)
            assert len(received) == 2
            peek_rights |= 1 << mode
            for fd in received:
                os.close(fd)
finally:
    sender.close(); receiver.close()
print('Native repeated-peek rights mask:', peek_rights)
# Native recvmmsg baseline, using the AArch64 ABI (syscall 243).
class IOVec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]
class MsgHdr(ctypes.Structure):
    _fields_ = [('name', ctypes.c_void_p), ('namelen', ctypes.c_uint),
                ('iov', ctypes.POINTER(IOVec)), ('iovlen', ctypes.c_size_t),
                ('control', ctypes.c_void_p), ('controllen', ctypes.c_size_t),
                ('flags', ctypes.c_int)]
class MMsgHdr(ctypes.Structure):
    _fields_ = [('header', MsgHdr), ('length', ctypes.c_uint)]
sender, receiver = socket.socketpair(type=socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
try:
    buffers = [ctypes.create_string_buffer(1) for _ in range(2)]
    vectors = [IOVec(ctypes.addressof(buffer), 1) for buffer in buffers]
    for queued in (2, 1):
        messages = (MMsgHdr * 2)()
        for i in range(2):
            messages[i].header.iov = ctypes.pointer(vectors[i])
            messages[i].header.iovlen = 1
            messages[i].length = 777
        for _ in range(queued):
            sender.send(b'R')
        result = libc.syscall(243, receiver.fileno(), messages, 2, socket.MSG_DONTWAIT, 0)
        assert result == queued, ('native recvmmsg', result, ctypes.get_errno())
        assert all(messages[i].length == 1 and buffers[i].raw == b'R' for i in range(queued))
        if queued == 1:
            assert messages[1].length == 777
finally:
    sender.close(); receiver.close()
print('PASS: native recvmmsg full and partial batches')
# Workspace storage rejects FIFOs on this host; the app cache supports both
# creation and deletion. Other hosts use their ordinary temporary directory.
fifo_base = Path('/data/storage/el2/base/cache')
with tempfile.TemporaryDirectory(prefix='fd-runtime-', dir=build) as temp, \
        tempfile.TemporaryDirectory(prefix='elf-fifo-', dir=fifo_base if fifo_base.is_dir() else None) as fifo_temp:
    work = Path(temp)
    fifo = Path(fifo_temp) / 'fifo'
    os.mkfifo(fifo, 0o600)
    (work / 'vfork-fifo').symlink_to(fifo)
    (work / 'fd-data').write_text('Q runtime file\n')
    for name in ('probe', 'rights', 'batch', 'notify', 'range', 'pidfd', 'unsupported', 'beneath', 'origin', 'ioctl', 'exec', 'fork', 'vfork', 'orphan'):
        probe = work / name
        subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector',
                        '-DFD_TRACK=1',
                        '-DEXPECT_ACCEPT_NONBLOCK=' + str(accept_nonblock),
                        '-DEXPECT_PEEK_RIGHTS=' + str(peek_rights),
                        '-I' + str(repo / 'src/payload/include'),
                        str(repo / 'test/fd_runtime' / (name + '.c')), '-o', str(probe)], check=True)
        if name == 'vfork':
            native = work / 'vfork-native'
            subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                            '-fno-builtin', '-fno-stack-protector', '-DFD_TRACK=0',
                            '-I' + str(repo / 'src/payload/include'),
                            str(repo / 'test/fd_runtime/vfork.c'), '-o', str(native)], check=True)
            reference = subprocess.run([str(native)], cwd=work, text=True,
                                       capture_output=True, timeout=20)
            assert reference.returncode == 0, (reference.returncode, reference.stdout, reference.stderr)
            print('PASS: native vfork sharing/suspension/FD/exec baseline')
        inherited = os.memfd_create('range-inherited', flags=0) if name in ('range', 'ioctl') else None
        command = [str(loader), '--mode', 'compat', '--', str(probe)]
        if name == 'beneath':
            outside = work / 'beneath-outside'; outside.mkdir()
            command = [str(loader), '--mode', 'compat', '-v',
                       f'{outside}:{work}/beneath-mount', '--', str(probe)]
        if name == 'origin':
            source = work / 'origin-source'; source.mkdir()
            (source / 'file').write_text('Q shared bind file')
            (source / 'to-two').symlink_to('/two/file')
            (source / 'nested').mkdir(); (source / 'nested/value').write_text('S')
            (source / 'moving').mkdir(); (source / 'moving/value').write_text('M')
            nested = work / 'origin-nested'; nested.mkdir(); (nested / 'value').write_text('N')
            command = [str(loader), '--mode', 'container', '--root', str(work),
                       '-v', f'{source}:/one', '-v', f'{source}:/two',
                       '-v', f'{nested}:/one/nested', '-v', f'{nested}:/shadow',
                       '-v', f'{source}:/shadow', '--', './origin']
        if name == 'exec':
            private_loader = work / 'exec-loader'
            private_loader.write_bytes(loader.read_bytes()); private_loader.chmod(0o755)
            external = work / 'external'; external.mkdir(); (external / 'value').write_text('V')
            command = [str(private_loader), '--mode', 'container', '--root', str(work),
                       '-v', f'{external}:/bound', '--', './exec']
        try:
            p = subprocess.run(command +
                               ([str(inherited)] if inherited is not None else []),
                               pass_fds=(inherited,) if inherited is not None else (),
                               cwd=work, text=True, capture_output=True, timeout=20)
        finally:
            if inherited is not None:
                os.close(inherited)
        assert p.returncode == 0 and 'PASS: runtime FD' in p.stdout, (p.returncode,p.stdout,p.stderr)
        print(p.stdout, end='')

    guards = work / 'syscall-guards'
    subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                    '-fno-builtin', '-fno-stack-protector',
                    str(repo / 'test/syscalls/runtime_probe.c'), '-o', str(guards)], check=True)
    p = subprocess.run([str(loader), '--mode', 'compat', '--', str(guards), 'b'],
                       capture_output=True, text=True, timeout=20)
    assert p.returncode == 0 and 'NR=452\nRET=-38\n' in p.stdout, (p.returncode, p.stdout, p.stderr)
    assert p.stdout.count('RET=-38\n') == 14, p.stdout
    census = json.loads((repo / 'test/syscalls/native-harmonyos.json').read_text())
    for entry in census['probes']:
        if entry.get('signal') == 'SIGSYS':
            assert f"NR={entry['number']}\nRET=-38\n" in p.stdout, entry
    print('PASS: experimental fatal syscall guards including native SIGSYS census and fchmodat2')

    bad_probe = work / 'restore-error'
    subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_runtime/restore_error.c'), '-o', str(bad_probe)], check=True)
    bad_state = os.memfd_create('unsealed-fd-state', flags=0)
    try:
        p = subprocess.run([str(loader), '--child-loader', '--fd-state', str(bad_state),
                            '--', str(bad_probe)], cwd=work, pass_fds=(bad_state,),
                           capture_output=True, text=True, timeout=20)
        assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    finally:
        os.close(bad_state)
    print('PASS: malformed exec handoff remains a persistent initialization error')
    limit_probe = work / 'restore-limit'
    subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding', '-fno-builtin',
                    '-fno-stack-protector', '-I' + str(repo / 'src/payload/include'),
                    str(repo / 'test/fd_runtime/restore_limit.c'), '-o', str(limit_probe)], check=True)
    for case in ('missing-fd', 'transport-alias', 'cloexec-record', 'serial-limit'):
        state = os.memfd_create('sealed-state', os.MFD_ALLOW_SEALING)
        inherited = os.memfd_create('state-record', flags=0)
        try:
            fd = 1000000 if case == 'missing-fd' else state if case == 'transport-alias' else inherited
            serial = (1 << 64) - 1 if case == 'serial-limit' else 1
            snapshot = struct.pack('<10Q', 0x31534446464c45, 1, serial, 1,
                                   fd, int(case == 'cloexec-record'), 1, 1, 0, 0)
            os.write(state, snapshot)
            fcntl.fcntl(state, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                        fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            target = limit_probe if case == 'serial-limit' else bad_probe
            argument = str(inherited) if case == 'serial-limit' else str(
                errno.EINVAL if case == 'cloexec-record' else errno.ESTALE)
            p = subprocess.run([str(loader), '--child-loader', '--fd-state', str(state),
                                '--', str(target), argument], cwd=work, pass_fds=(state, inherited),
                               capture_output=True, text=True, timeout=20)
            assert p.returncode == 0, (case, p.returncode, p.stdout, p.stderr)
        finally:
            os.close(state); os.close(inherited)
        print('PASS: exec handoff', case)


# Optional smoke tests against already extracted user-provided fixtures.
for directory, target, arguments, marker in [
        ('alpine-test-root', './bin/busybox', ['cat', '/etc/alpine-release'], '3.24.3'),
        ('ubuntu-root', './usr/bin/cat', ['/etc/os-release'], 'Ubuntu')]:
    root = build / directory
    if not (root / target).exists():
        print('SKIP: optional rootfs smoke', directory)
        continue
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                        '--', target, *arguments], cwd=root, text=True,
                       capture_output=True, timeout=20)
    assert p.returncode == 0 and marker in p.stdout, (directory, p.returncode, p.stdout, p.stderr)
    print('PASS: experimental runtime rootfs cat', directory)

subprocess.run(['python3', str(repo / 'vendor/proot/port-tests/test_inotify.py'),
                '--fd-experiment'], check=True)

for directory, shell, command, marker in [
        ('alpine-test-root', './bin/busybox', ['sh', '-c', 'exec /bin/busybox cat /etc/alpine-release'], '3.24.3'),
        ('ubuntu-root', './usr/bin/dash', ['-c', 'exec /usr/bin/cat /etc/os-release'], 'Ubuntu')]:
    root = build / directory
    if not (root / shell).exists():
        print('SKIP: optional rootfs exec smoke', directory)
        continue
    p = subprocess.run([str(loader), '--mode', 'container', '--root', str(root),
                        '--', shell, *command], cwd=root, capture_output=True, text=True, timeout=20)
    assert p.returncode == 0 and marker in p.stdout, (directory, p.returncode, p.stdout, p.stderr)
    print('PASS: experimental runtime rootfs shell exec', directory)

subprocess.run(['python3', str(repo / 'test/fd_runtime/shell.py')], check=True)

subprocess.run(['python3', str(repo / 'test/fd_runtime/files.py')], check=True)
