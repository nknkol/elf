#!/usr/bin/env python3
"""Isolation acceptance for case aliases (docs/ISOLATION_TESTING.md, goal D).

On host storage that matches names regardless of case (HarmonyOS hmdfs,
/storage/Users), work/secret is the very directory work/Secret. Layout on
such a backing:
  work/          bound at /work, writable
  work/Secret/   bound at /work/Secret, invisible (guarded build)
  work/Ro/       bound at /work/Ro, read-only (guarded build)
Every case spelling must take the policy of the tree its object is in:
through the payload ("h") and in requests forged straight to the broker,
which walks by (dev, ino) and must not care how a name is spelled. No
output may contain the secret. Without a case-insensitive backing: SKIP."""
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

alpine = lib.require(lib.ALPINE / 'bin/busybox').parents[1]


def insensitive_base():
    for base in (lib.BUILD, Path('/storage/Users/currentUser'), Path(tempfile.gettempdir())):
        try:
            with tempfile.TemporaryDirectory(prefix='case-probe-', dir=base) as tmp:
                (Path(tmp) / 'Ab').mkdir()
                if (Path(tmp) / 'ab').exists():
                    return base
        except OSError:
            continue
    return None


def parse(output):
    values = {}
    for line in output.splitlines():
        parts = line.split(' ', 1)
        if len(parts) == 2:
            try:
                values[parts[0]] = int(parts[1])
            except ValueError:
                values[parts[0]] = parts[1]
    return values


neg = lambda v: isinstance(v, int) and v < 0  # noqa: E731
zero = lambda v: v == 0                       # noqa: E731

base_dir = insensitive_base()
if not base_dir:
    print('SKIP: no case-insensitive backing directory')
    raise SystemExit(0)

failures = []
secret = f'CASE-SECRET-{secrets.token_hex(8)}'
with tempfile.TemporaryDirectory(prefix='iso-case-', dir=base_dir) as tmp:
    base = Path(tmp)
    binary = base / 'iso-probe'
    subprocess.run(['clang', '-O1', '-static', '-I', str(lib.REPO / 'src/payload/include'),
                    '-I', str(lib.REPO / 'src/payload/arch/aarch64'),
                    str(Path(__file__).with_name('probe.c')), '-o', str(binary)], check=True)
    work = base / 'work'
    (work / 'Secret').mkdir(parents=True)
    (work / 'Secret/key').write_text(secret + '\n')
    (work / 'Ro').mkdir()
    (work / 'Ro/file').write_text('ro-data\n')
    (work / 'file').write_text('rw-data\n')
    assert os.path.samefile(work / 'secret', work / 'Secret')
    before = {p: (p.read_bytes(), p.stat().st_mode) for p in (work / 'Secret/key', work / 'Ro/file')}
    shutil.copy2(binary, alpine / 'iso-probe')
    try:
        for suffix, loader in lib.loaders():
            guarded = suffix == '-guarded'

            def expect(args, checks):
                argv = [str(loader), '--isolate', '--mode', 'container', '--root', str(alpine),
                        '-v', f'{work}:/work', '-v', f'{work}/Secret:/work/Secret', '-v', f'{work}/Ro:/work/Ro']
                if guarded:
                    argv += ['--guard-file-access', 'rwdr', '--allow-stdio-output']
                p = subprocess.run([*argv, '--', './iso-probe', *args], cwd=alpine, capture_output=True,
                                   text=True, timeout=120, stdin=subprocess.DEVNULL)
                values = parse(p.stdout)
                bad = [f'{label}={values.get(label)!r}' for label, ok in checks.items() if not ok(values.get(label))]
                if guarded and secret in p.stdout + p.stderr:
                    bad.append('secret leaked')
                tag = f'D-case {loader.name} {" ".join(args)}'
                print('FAIL:' if bad else 'PASS:', tag, bad or '')
                bad and failures.append(f'{tag}: {", ".join(bad)}; out={p.stdout.strip()[-300:]!r} '
                                        f'err={p.stderr.strip()[-300:]!r}')

            if not guarded:
                # Every tree is writable: each spelling reaches the object.
                for name in ('Secret', 'secret', 'SECRET'):
                    expect(('h', 'open', f'/work/{name}/key', '0'), {'open': zero})
                continue
            for name in ('Secret', 'secret', 'SECRET', 'sEcReT'):
                expect(('h', 'open', f'/work/{name}/key', '0'), {'open': neg})
                expect(('h', 'stat', f'/work/{name}/key'), {'stat': neg})
                expect(('h', 'list', f'/work/{name}'), {'list': neg})
            for name in ('Ro', 'ro', 'RO'):
                expect(('h', 'open', f'/work/{name}/file', '0'), {'open': zero})
                expect(('h', 'open', f'/work/{name}/file', '1'), {'open': neg})
                expect(('h', 'chmod', f'/work/{name}/file'), {'chmod': neg})
                expect(('h', 'unlink', f'/work/{name}/file'), {'unlink': neg})
                expect(('h', 'rename', f'/work/{name}/file', '/work/moved'), {'rename': neg})
                expect(('h', 'link', f'/work/{name}/file', '/work/hard'), {'link': neg})
            expect(('h', 'open', '/work/file', '1'), {'open': zero})
            # Host paths forged straight to the broker, spelled in other cases.
            for name, ro in (('secret', 'ro'), ('SECRET', 'RO')):
                expect(('h', 'forge', f'{work}/{name}/key', f'{work}/{ro}/file', f'{work}/file', f'{work}/sock'),
                       {'channel': zero, 'f-open-outside': neg, 'f-open-ro-rw': neg,
                        'f-link-ro-to-rw': neg, 'f-valid-after': lambda x: x == 1})
            # Control: a case variant in the writable tree is served, so the
            # refusals above come from the tree, not from the spelling.
            expect(('h', 'forge', f'{work}/FILE', f'{work}/ro/file', f'{work}/file', f'{work}/sock'),
                   {'f-open-outside': lambda x: isinstance(x, int) and x >= 0})
            for leftover in ('moved', 'hard', 'file.hardlink'):
                (work / leftover).unlink(missing_ok=True)
    finally:
        (alpine / 'iso-probe').unlink(missing_ok=True)
    after = {p: (p.read_bytes(), p.stat().st_mode) for p in before}
    if after != before:
        failures.append('Secret/key or Ro/file changed')
    print('FAIL:' if after != before else 'PASS:', 'Secret/ and Ro/ unchanged')

print(f'{len(failures)} failure(s)')
for f in failures:
    print(' -', f)
raise SystemExit(1 if failures else 0)
