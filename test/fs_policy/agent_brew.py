#!/usr/bin/env python3
"""HarmonyOS only: real harmonybrew programs under profiles/harmonyos-agent.json."""
import os
import subprocess
import tempfile
from pathlib import Path
repo = Path(__file__).resolve().parents[2]
build = repo / 'vendor/proot/svc/build'
brew = Path(os.environ.get('HARMONYBREW_PREFIX', Path.home() / '.harmonybrew'))
python = brew / 'bin/python3'
if not Path('/system/lib/ld-musl-aarch64.so.1').exists() or not python.exists() \
        or not (brew / 'bin/git').exists():
    print('SKIP: HarmonyOS harmonybrew python3/git unavailable')
    raise SystemExit(0)

SCRIPT = r'''
import json, os, subprocess, sys
git = sys.argv[1]
result = {"cwd": os.getcwd(), "root": sorted(os.listdir("/")), "dev": sorted(os.listdir("/dev")),
          "home": os.environ["HOME"], "note": open("note").read().strip()}
host_home = sys.argv[2]
result["host_projects_visible"] = os.path.exists(os.path.join(host_home, "Workspace"))
try:
    open("/system/elf-agent-probe", "w")
    result["system_write"] = "allowed"
except OSError as exc:
    result["system_write"] = exc.errno
# Container mode reports uid 0 while stat shows the real owner; git's
# ownership check needs an explicit exception (command-line config is trusted).
run = lambda *a: subprocess.run([git, "-c", "safe.directory=/workspace", "-c", "user.name=agent",
                                 "-c", "user.email=a@example.invalid", *a],
                                check=True, capture_output=True, text=True).stdout
run("init", "-q")
run("add", "note")
run("commit", "-q", "-m", "from sandbox")
result["log"] = run("log", "--format=%s").strip()
print(json.dumps(result))
'''

with tempfile.TemporaryDirectory(prefix='agent-brew-', dir=build) as tmp:
    base = Path(tmp)
    workspace = base / 'workspace'
    workspace.mkdir()
    (workspace / 'note').write_text('workspace-note\n')
    p = subprocess.run(['python3', str(repo / 'tools/agent_sandbox/launch.py'),
                        str(repo / 'profiles/harmonyos-agent.json'), '--brew-prefix', str(brew),
                        '--workspace', str(workspace), '--state', str(base / 'state'), '--',
                        str(python.resolve()), '-c', SCRIPT, str(brew / 'bin/git'), str(Path.home())],
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr[-2000:])
    assert 'HiLogBase' not in p.stderr, p.stderr[-2000:]
    import json
    result = json.loads(p.stdout.strip().splitlines()[-1])
    top = str(brew).split('/')[1]
    assert result['cwd'] == '/workspace' and result['home'] == '/home/agent', result
    assert result['root'] == sorted({'dev', 'etc', 'home', 'lib', 'system', 'tmp', 'workspace', top}), result
    assert result['dev'] == ['null', 'unix'] and result['note'] == 'workspace-note', result
    assert result['host_projects_visible'] is False, result
    assert result['system_write'] == 30, result  # EROFS
    assert result['log'] == 'from sandbox', result
    assert (workspace / '.git').is_dir()
    print('PASS: harmonybrew python3 and git under the HarmonyOS agent profile')
