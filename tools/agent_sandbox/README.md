# Agent filesystem profiles (planning prototype)

The primary product direction is an agent filesystem sandbox using existing
system/brew tools. A separate Linux rootfs is a secondary mode. This repository
contains the ELF execution backend and vendored PRoot path semantics together;
bubblewrap is not a build or runtime dependency.

`plan.py` currently validates and prints a filesystem plan only. It does not
launch an agent, create directories, or enforce access. The output explicitly
marks enforcement as `not-connected`; do not pass the plan to the legacy bind
CLI expecting readonly or default-deny isolation.

From the repository root, with real absolute paths:

```sh
python3 tools/agent_sandbox/plan.py profiles/agent.json \
  --brew-prefix /path/to/brew \
  --workspace /path/to/project \
  --state /path/to/private-run
python3 -m unittest discover -s test/agent_sandbox -v
```

The profile exposes the brew prefix at its original guest pathname (readonly),
the workspace at `/workspace` (read/write), and private home/tmp/cache backing
directories. Unknown paths default to deny. Explicit nested mappings use the
longest component prefix. Symlinks must be resolved by the runtime before policy
checking; the Python access model operates only on canonical guest paths.
Private state must be outside exposed source trees. Planning resolves existing
host symlinks, but does not guarantee safety against later pathname races.

Add platform system libraries/interpreters/resources explicitly to `mounts`
with `access: ro`. The sample is a policy example, not a complete tested brew
runtime profile. The complete brew prefix is exposed so Cellar/opt links and
resources can remain usable; dependencies outside that prefix still need rules.
Environment expansion and shell execution are not used. Only whole-path
`${BREW_PREFIX}` and `${WORKSPACE}` substitutions are supported.

Next implementation steps:

1. Carry validated policy in loader/payload configuration and across exec;
   reject policy configurations that exceed backend limits.
2. Connect default-deny visibility and readonly checks to canonical path
   resolution, including both operands of rename/link and metadata mutation.
3. Track descriptor provenance and permissions, including inherited FDs,
   dup/close, writable mmap and descriptor-based mutations. Filter directory
   listings and handle traversal of ancestors needed to reach exposed paths.
4. Create private state and clean environment for launch; validate actual brew
   programs and their dynamic loaders in the system sandbox.
5. Close known interception bypasses before claiming hostile-agent isolation.

For the functioning experimental path backend and its tests, see
[vendor/proot/SVC_PORT.md](../../vendor/proot/SVC_PORT.md).
