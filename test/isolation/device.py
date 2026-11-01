#!/usr/bin/env python3
"""--isolate-device acceptance (docs/ISOLATION.md, "GPU 设备", 验收标准).

Part of the application sandbox's acceptance suite, HarmonyOS device only:
  - the exec trust chain holds without the option too (docs/ISOLATION.md,
    "执行可信链"): the negative filter, exec and broker checks below run
    with plain --isolate as well, where every open is refused;
  - the start is refused for bad uses of the option;
  - positive: the Vulkan driver creates a device, allocates, maps and writes
    memory in the first process, a forked child, after exec and while a
    second thread opens the device (gpu_device.c, both builds);
  - negative: device_probe.c from the payload's own svc: other pointers, bad
    flags, unselected devices, every memory call that meets the constant
    page, userfaultfd, execveat forms, the loader FD; through the broker:
    writes to the loader file under its name, a case alias and a hard link,
    /proc/<pid>/mem, the device path's names.
Refused means EPERM from the filter, or a kill by the host sandbox's own
filter (reported as <= -1000), as in run.py."""
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

DEVICE = '/dev/hvgr0'
HERE = Path(__file__).resolve().parent
EPERM = -1
failures = []

if not os.path.exists(DEVICE):
    print(f'SKIP: {DEVICE} missing (HarmonyOS device only)')
    sys.exit(0)

refused = lambda v: v == EPERM or (isinstance(v, int) and v <= -1000)  # noqa: E731
zero = lambda v: v == 0                                                 # noqa: E731
failed = lambda v: isinstance(v, int) and v < 0                         # noqa: E731


def parse(output):
    values = {}
    for line in output.splitlines():
        parts = line.rsplit(' ', 1)
        if len(parts) == 2:
            try:
                values[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return values


def check(tag, values, rules, output=''):
    bad = [f'{label}={values.get(label)!r}' for label, ok in rules.items() if not ok(values.get(label))]
    print('FAIL:' if bad else 'PASS:', tag, bad or '')
    if bad:
        failures.append(f'{tag}: {", ".join(bad)}; out={output.strip()[-400:]!r}')


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL, **kw)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def trust_checks(name, flags, suffix, no_device):
    """The filter from the payload's own svc, and the allowed exec form."""
    p = run([*flags, '--', str(probe), 'filter'])
    values = parse(p.stdout)
    rules = {label: refused for label in (
        'open-other-pointer', 'open-high-bits', 'open-inside-constant', 'open-creat', 'open-path',
        'open-trunc', 'open-directory', 'open-tmpfile', 'open-nofollow', 'open-append',
        'open-unselected-1', 'open-unselected-2', 'open-unselected-3',
        'munmap-page', 'munmap-from-below', 'munmap-wide', 'mprotect-page', 'mprotect-none',
        'pkey_mprotect-page', 'madvise-page', 'madvise-from-below', 'remap_file_pages-page',
        'mmap-fixed-page', 'mmap-fixed-over', 'mremap-old', 'mremap-fixed-new', 'mremap-fixed-new-below',
        'shmat-remap', 'userfaultfd', 'unshare', 'setns',
        'execveat-own-empty', 'execveat-other-fd', 'execveat-no-empty-flag', 'execveat-path', 'execve',
        'close-loader', 'close-loader-high-bits', 'dup3-onto-loader', 'fcntl-setfd-loader',
        'ioctl-fioclex-loader', 'close_range-over-loader', 'close_range-cloexec-loader')}
    rules.update({label: zero for label in (
        'open-selected', 'open-selected-dirfd', 'mprotect-before', 'mprotect-after', 'mmap-fixed-own',
        'mmap-hint-page', 'munmap-own', 'page-intact', 'fcntl-getfd-loader', 'dup3-other',
        'fcntl-setfd-other', 'close-other', 'loader-fd-open')})
    if no_device:   # every open goes to the broker: the filter refuses them all
        rules['open-selected'] = rules['open-selected-dirfd'] = refused
    # HarmonyOS has no close_range (the host sandbox kills it).
    rules['close_range-away'] = lambda v: v == 0 or v == -38 or (isinstance(v, int) and v <= -1000)
    check(f'{name}: filter rules', values, rules, p.stdout + p.stderr)
    p = run([*flags, '--', str(probe), 'exec'])
    check(f'{name}: execveat(898, page empty path) runs the loader', parse(p.stdout), {'execveat-loader': zero},
          p.stdout + p.stderr)


work = Path(tempfile.mkdtemp(prefix='iso-device-', dir='/data/storage/el2/base/files'
                             if os.path.isdir('/data/storage/el2/base/files') else lib.BUILD))
# A directory on the case-insensitive storage, for the case alias.
folded = Path(tempfile.mkdtemp(prefix='iso-device-cs-', dir=lib.BUILD))
try:
    include = lib.REPO / 'src/payload/include'
    probe = work / 'device_probe'
    subprocess.run(['clang', '-O1', '-static', '-I', str(include), str(HERE / 'device_probe.c'), '-o', str(probe)],
                   check=True)
    sdk = sorted(glob.glob(os.path.expanduser('~/.harmonybrew/Cellar/ohos-sdk-native/*/sysroot/usr/include')))
    gpu = work / 'gpu_device'
    if sdk:
        subprocess.run(['clang', '-O1', '-idirafter', sdk[-1], str(HERE / 'gpu_device.c'), '-o', str(gpu),
                        '-L/system/lib64', '-lvulkan', '-lpthread', '-Wl,--allow-shlib-undefined'], check=True)
    for suffix, loader in lib.loaders():
        name = loader.name
        # Filter program: the device option adds the openat rules only.
        base = run([str(loader), '--guest-filter-dump']).stdout.splitlines()
        with_device = run([str(loader), '--isolate-device', DEVICE, '--guest-filter-dump'])
        longer = with_device.returncode == 0 and len(base) > 100 and \
            len(base) < len(with_device.stdout.splitlines()) < len(base) + 60
        print('PASS:' if longer else 'FAIL:', f'{name}: filter with --isolate-device adds the device rules')
        longer or failures.append(f'{name}: device filter {with_device.returncode} {with_device.stderr[-200:]!r}')

        # Refused starts.
        for args, why in (([f'--isolate-device', DEVICE], 'requires --isolate'),
                          (['--isolate', '--isolate-device', '/dev/null'], 'unsupported isolated device'),
                          (['--isolate', '--isolate-device', '/dev/hvgr0x'], 'unsupported isolated device')):
            p = run([str(loader), *args, '--', str(probe), 'exec'])
            ok = p.returncode != 0 and why in p.stdout + p.stderr and 'execveat' not in p.stdout
            print('PASS:' if ok else 'FAIL:', f'{name}: start refused: {" ".join(args)}')
            ok or failures.append(f'{name}: {args} started: {p.returncode} {p.stdout[-200:]!r} {p.stderr[-200:]!r}')
        for missing in ('/dev/mali0', '/dev/kgsl-3d0', '/dev/dri/renderD128'):
            if os.path.exists(missing):
                continue
            p = run([str(loader), '--isolate', '--isolate-device', missing, '--', str(probe), 'exec'])
            ok = p.returncode != 0 and 'cannot stat' in p.stdout + p.stderr
            print('PASS:' if ok else 'FAIL:', f'{name}: start refused for missing {missing}')
            ok or failures.append(f'{name}: missing {missing} started: {p.returncode} {p.stderr[-200:]!r}')

        isolated = [str(loader), '--isolate', '--isolate-device', DEVICE]
        # Positive: the driver opens the device itself in every kind of process.
        if not sdk:
            print('SKIP: OpenHarmony SDK headers missing, no Vulkan probe')
        for mode in ('init', 'fork', 'exec', 'thread') if sdk else ():
            p = run([*isolated, '--', str(gpu), mode])
            ok = f'RESULT {mode} ok' in p.stdout
            print('PASS:' if ok else 'FAIL:', f'{name}: Vulkan device in {mode}')
            ok or failures.append(f'{name}: Vulkan {mode}: {p.stdout[-300:]!r} {p.stderr[-300:]!r}')
            if mode == 'init':
                # Control: without the option the broker opens it and the driver refuses it.
                p = run([str(loader), '--isolate', '--', str(gpu), mode])
                ok = f'RESULT {mode} fail' in p.stdout
                print('PASS:' if ok else 'FAIL:', f'{name}: control: without --isolate-device createDevice fails')
                ok or failures.append(f'{name}: control without the option: {p.stdout[-300:]!r}')

        for variant, flags in (('', isolated), (' (no device)', [str(loader), '--isolate'])):
            trust_checks(name + variant, flags, suffix, bool(variant))

        # Negative: the broker. The running loader is a copy in a writable
        # bind on the case-insensitive storage; its hard link (when the host
        # allows hard links) in another writable directory.
        copy = folded / f'loader{suffix}'
        shutil.copy2(loader, copy)
        alias = folded / copy.name.upper()
        links = folded / f'links{suffix}'
        links.mkdir()
        link = links / 'loader-link'
        try:
            os.link(copy, link)
            linked = True
        except OSError as error:
            linked = False
            print(f'SKIP: {name}: hard link of the loader ({error.strerror}: the host refuses hard links)')
        for variant, device in (('', ['--isolate-device', DEVICE]), (' (no device)', [])):
            before = digest(copy), copy.stat().st_mode
            policy = ['--guard-file-access', 'rww', '--allow-stdio-output'] if suffix else []
            p = run([str(copy), '--isolate', *device, '-v', f'{folded}:{folded}',
                     '-v', f'{links}:{links}', *policy, '--', str(probe), 'broker',
                     str(link) if linked else '/nonexistent', str(alias)])
            values = parse(p.stdout)
            rules = {'config-found': lambda v: v == 1}
            for path in ('loader', 'alias', *(['link'] if linked else [])):
                for mode in ('rdwr', 'wronly', 'trunc'):
                    rules[f'open-{path}-{mode}'] = failed
                rules[f'open-{path}-rdonly'] = zero
            rules.update({'truncate-alias': failed, 'reopen-loader-fd-rdwr': failed})
            if linked:
                rules.update({'truncate-link': failed, 'chmod-link': failed, 'fchmod-link': failed,
                              'reopen-link-rdwr': failed})
            check(f'{name}{variant}: broker refuses writes to the loader file', values, rules, p.stdout + p.stderr)
            after = digest(copy), copy.stat().st_mode
            print('PASS:' if after == before else 'FAIL:', f'{name}{variant}: loader file unchanged')
            after == before or failures.append(f'{name}{variant}: loader file changed')
        # /proc/<pid>/mem with /proc bound; the device path keeps its names.
        for variant, flags in (('', isolated), (' (no device)', [str(loader), '--isolate'])):
            p = run([*flags, '-v', '/proc:/proc', *(['--guard-file-access', 'ww', '--allow-stdio-output']
                                                    if suffix else []),
                     '--', str(probe), 'broker', '/nonexistent', '/nonexistent'])
            check(f'{name}{variant}: /proc/<pid>/mem and the device path', parse(p.stdout),
                  {'proc-self-mem': failed, 'proc-self-mem-rdonly': failed, 'proc-pid-mem': failed,
                   'proc-task-mem': failed, 'proc-status': zero, 'rename-device': failed, 'unlink-device': failed},
                  p.stdout + p.stderr)
        ok = os.path.exists(DEVICE)
        print('PASS:' if ok else 'FAIL:', f'{name}: {DEVICE} still there')
        ok or failures.append(f'{name}: {DEVICE} gone')
finally:
    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(folded, ignore_errors=True)

if failures:
    print(f'{len(failures)} failure(s):')
    for failure in failures:
        print('  ' + failure)
    sys.exit(1)
print('device acceptance: all passed')
