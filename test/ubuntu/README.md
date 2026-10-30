# Offline Ubuntu/glibc rootfs survey

The supplied `ubuntu-base-26.04.1-base-arm64.tar.gz` runs glibc 2.43 on the
HarmonyOS host through the experimental ELF/PRoot backend. The current result
is **18 of 18 acceptance cases passing** after implementing guest PR_GET_AUXV. See `acceptance.json` for fixture SHA-256 and per-case results.
The archive identity is recorded locally, not authenticated against upstream.

Run from the ELF repository root:

```sh
python3 tools/build.py
python3 test/ubuntu/run.py ../ubuntu-base-26.04.1-base-arm64.tar.gz
```

The survey exits nonzero when any case fails; the two known failures are not
silently treated as passing. Full output is kept in the ignored build directory
at `build/ubuntu-results.json`. Each run uses a temporary root
and host bind fixture, and explicitly binds host `/dev/null`. No package
installation or network request is performed. The initial entry is
`./usr/bin/dash`, with later exec routed through the guest filesystem resolver.

Passing: dash/bash, glibc version, grep pipeline, GNU sed, awk through alternatives,
Perl, local NSS passwd lookup, dpkg local database, background/wait, find,
shell exit status, shebang argv/environment, bind cwd/read/write and command
substitution. This is concrete dynamic glibc coverage, not full container
compatibility or a multithreaded glibc validation.

Both `/usr/bin/ls` and `/usr/bin/cat` resolve to this image's Rust coreutils.
They previously aborted during rustix auxv initialization. The backend now
returns a snapshot of the guest startup auxv through PR_GET_AUXV; both commands
pass without binding host /proc. See [auxv diagnosis](AUXV_DIAGNOSIS.md) for the
original failure and the implemented fix. /proc/self/auxv file emulation is
still absent; callers must use the supported prctl route.

## Extraction adaptation

This archive contains 115 hardlink entries, many targeting the 10 MiB coreutils
binary. The host rejects ordinary hardlink creation with EPERM. The shared
extractor therefore offers an explicit `materialize_hardlinks=True` option,
used only by this Ubuntu harness. Each hardlink becomes a separate regular
file with identical bytes and source mode. This changes shared-inode semantics;
hardlink behavior and inode identity are outside this fixture's claims. It
requires roughly a GiB of transient extra storage. The original archive is
untouched and is not committed.

Hardlink targets must be regular members inside the archive, with no absolute
or parent-traversing name. All metadata is validated before extraction; no file
may be placed beneath a symlink. Absolute guest symlinks and merged-/usr layout
are preserved, and symlinks are created last. The default Alpine extraction
continues to reject hardlinks. Expanded extraction is capped at 2 GiB.

Remaining work includes real pthread/clone workloads, proc/dev interfaces and
package operations.
