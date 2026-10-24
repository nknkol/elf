#!/usr/bin/env python3
"""Inventory target headers and probe bounded syscall cases in disposable processes."""
import argparse
import ctypes
import json
import platform
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile


def numbers():
    proc = subprocess.run(['clang', '-dM', '-E', '-'], input='#include <asm/unistd.h>\n', text=True, capture_output=True, check=True)
    macros = dict(re.findall(r'^#define (__NR\w+) (.+)$', proc.stdout, re.M))
    def resolve(name):
        value = macros[name]
        if value in macros:
            return resolve(value)
        return int(value.strip('()'), 0)
    out = {}
    for key in macros:
        if key.startswith('__NR_') and key not in ('__NR_syscalls', '__NR_arch_specific_syscall'):
            try: out[key[5:]] = resolve(key)
            except ValueError: pass
    return out


# Names and argument recipes are explicit. Never execute every syscall number
# blindly: zero arguments are unsafe for many system/process control operations.
INVALID_FD = {
    'close': [-1], 'dup': [-1], 'dup3': [-1, -1, 0], 'fcntl': [-1, 1],
    'fstat': [-1, 'buf'], 'fstatfs': [-1, 'buf'], 'fchdir': [-1],
    'read': [-1, 'buf', 1], 'write': [-1, 'buf', 1],
    'pread64': [-1, 'buf', 1, 0], 'pwrite64': [-1, 'buf', 1, 0],
    'readv': [-1, 0, 0], 'writev': [-1, 0, 0],
    'preadv': [-1, 0, 0, 0, 0], 'pwritev': [-1, 0, 0, 0, 0],
    'preadv2': [-1, 0, 0, 0, 0, 0], 'pwritev2': [-1, 0, 0, 0, 0, 0],
    'lseek': [-1, 0, 0], 'getdents64': [-1, 'buf', 4096],
    'ftruncate': [-1, 0], 'fallocate': [-1, 0, 0, 1],
    'fchmod': [-1, 0o600], 'fchown': [-1, -1, -1],
    'fsync': [-1], 'fdatasync': [-1], 'syncfs': [-1],
    'flock': [-1, 1], 'ioctl': [-1, 0, 0],
    'sendfile': [-1, -1, 0, 0], 'copy_file_range': [-1, 0, -1, 0, 0, 0],
    'splice': [-1, 0, -1, 0, 0, 0], 'tee': [-1, -1, 0, 0],
    'vmsplice': [-1, 0, 0, 0],
    'fgetxattr': [-1, 'attr', 'buf', 4096], 'flistxattr': [-1, 'buf', 4096],
    'fsetxattr': [-1, 'attr', 'buf', 1, 0], 'fremovexattr': [-1, 'attr'],
    'bind': [-1, 0, 0], 'connect': [-1, 0, 0],
    'sendmsg': [-1, 0, 0], 'recvmsg': [-1, 0, 0],
    'io_uring_enter': [-1, 0, 0, 0, 0, 0], 'io_uring_register': [-1, 0, 0, 0],
    'open_by_handle_at': [-1, 0, 0],
}
FIXTURE = {
    'openat': [-100, 'file', 0, 0],
    'newfstatat': [-100, 'file', 'buf', 0], 'fstatat': [-100, 'file', 'buf', 0],
    'statx': [-100, 'file', 0, 0x7ff, 'buf'], 'statfs': ['file', 'buf'],
    'faccessat': [-100, 'file', 0], 'faccessat2': [-100, 'file', 0, 0],
    'readlinkat': [-100, 'link', 'buf', 4096],
    'mkdirat': [-100, 'new', 0o700], 'unlinkat': [-100, 'file', 0],
    'renameat': [-100, 'file', -100, 'new'], 'renameat2': [-100, 'file', -100, 'new', 1],
    'linkat': [-100, 'file', -100, 'new', 0], 'symlinkat': ['file', -100, 'new'],
    'mknodat': [-100, 'new', 0o010600, 0],
    'truncate': ['file', 0], 'fchmodat': [-100, 'file', 0o600],
    'fchownat': [-100, 'file', -1, -1, 0], 'utimensat': [-100, 'file', 0, 0],
    'chdir': ['directory'], 'getcwd': ['buf', 4096],
    'getxattr': ['file', 'attr', 'buf', 4096], 'lgetxattr': ['file', 'attr', 'buf', 4096],
    'listxattr': ['file', 'buf', 4096], 'llistxattr': ['file', 'buf', 4096],
    'setxattr': ['file', 'attr', 'buf', 1, 0], 'lsetxattr': ['file', 'attr', 'buf', 1, 0],
    'removexattr': ['file', 'attr'], 'lremovexattr': ['file', 'attr'],
    'execve': ['missing', 0, 0], 'execveat': [-100, 'missing', 0, 0, 0],
}
OTHER = {
    'getpid': [], 'gettid': [], 'getuid': [], 'getgid': [],
    'rt_sigaction': [10, 0, 'buf', 8], # Query only, never replace a handler.
    'rt_sigprocmask': [0, 0, 'buf', 8], 'sigaltstack': [0, 'buf'],
    'prctl': [3, 0, 0, 0, 0], # PR_GET_DUMPABLE
    'rseq': [0, 0, 0, 0],
    'clone3': [0, 0], # Invalid size: cannot spawn a child.
    'io_uring_setup': [0, 0], 'openat2': [-100, 'file', 0, 0],
    'mmap': [0, 4096, 3, 0x22, -1, 0],
    'mprotect': [1, 4096, 1], 'munmap': [1, 4096],
    'mremap': [1, 4096, 4096, 0], # Unaligned: cannot change Python mappings.
}
CASES = {**INVALID_FD, **FIXTURE, **OTHER}


def child(name, number, directory):
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = Path(directory)
    (root/'file').write_bytes(b'test\n')
    (root/'link').symlink_to('file')
    data = {key: ctypes.create_string_buffer(str(root/value).encode()) for key, value in
            [('file', 'file'), ('link', 'link'), ('new', 'new'), ('missing', 'missing')]}
    data['directory'] = ctypes.create_string_buffer(str(root).encode())
    data['attr'] = ctypes.create_string_buffer(b'user.elf_probe')
    data['buf'] = ctypes.create_string_buffer(4096)
    args = [ctypes.c_long(ctypes.addressof(data[a]) if isinstance(a, str) else a) for a in CASES[name]]
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    ret = libc.syscall(ctypes.c_long(number), *args)
    err = ctypes.get_errno() if ret == -1 else 0
    print(json.dumps(dict(return_value=ret, errno=err)), flush=True)


def scan(output):
    nums = numbers()
    report = dict(machine=platform.machine(), kernel=platform.release(),
                  scope='Native Python child processes; each result applies only to listed arguments',
                  header_syscalls=nums, probes=[])
    output.parent.mkdir(parents=True, exist_ok=True)
    for name, args in CASES.items():
        if name not in nums:
            report['probes'].append(dict(name=name, status='absent-from-headers'))
            continue
        with tempfile.TemporaryDirectory(prefix='syscall-probe-') as directory:
            record = dict(name=name, number=nums[name], arguments=args,
                          recipe='invalid-fd' if name in INVALID_FD else 'private-fixture' if name in FIXTURE else 'bounded-special')
            try:
                p = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), '--child', name,
                                    str(nums[name]), directory], capture_output=True, text=True, timeout=3)
                record['exit_code'] = p.returncode
                if p.returncode < 0:
                    record.update(status='signal', signal=signal.Signals(-p.returncode).name)
                elif p.returncode:
                    record.update(status='probe-error', stderr=p.stderr[-2000:])
                else:
                    record.update(status='returned', **json.loads(p.stdout))
            except subprocess.TimeoutExpired:
                record['status'] = 'timeout'
            report['probes'].append(record)
        output.write_text(json.dumps(report, indent=2)+'\n')
        print(name, record['status'], record.get('signal', record.get('errno', '')), flush=True)
    output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--child':
        child(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--output', type=Path, required=True)
        scan(parser.parse_args().output)
