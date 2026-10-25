# Offline Alpine AArch64 acceptance

The user-supplied `alpine-minirootfs-3.24.3-aarch64.tar.gz` passes 18 acceptance
checks with backend commit e49f60c on the HarmonyOS sandbox. The measured archive
SHA-256 and test names are recorded in `acceptance.json`. This records the local
fixture's identity; it is not an upstream authenticity verification. Neither
the archive nor the extracted rootfs is committed.

From the ELF repository root:

```sh
python3 vendor/proot/svc/build_elf.py
python3 test/alpine/run.py ../alpine-minirootfs-3.24.3-aarch64.tar.gz
python3 -m unittest discover -s test/alpine -p 'test_*.py' -v
```

The harness checks the loader snapshot manifest, extracts into a fresh temporary
root, runs bounded subprocesses, records stdout/stderr and checks exact expected
outputs. Bind writes are also checked from the host. Results are written to
`vendor/proot/svc/build/alpine-results.json`; the extracted fixture is removed.

Rootfs applets use absolute guest symlinks such as `/bin/sh -> /bin/busybox`.
The extractor preserves them but rejects absolute/traversing member names,
duplicates, hardlinks/special nodes, and members below any symlink. All links
are created last, in an empty private directory. This deliberately supports
this minirootfs format rather than acting as a general tar extractor.

Launch uses `./bin/busybox sh` for the initial program, inside the guest root.
Applets and `/bin/sh` subsequently execute through the payload's guest path
resolver. The suite explicitly binds one private host directory at `/workspace`
and host `/dev/null` at guest `/dev/null`. Without the latter, BusyBox ash
background jobs fail when trying to redirect stdin. No full `/dev` or `/proc`
mount is provided, and no namespace/privilege changes are requested.

Covered: musl dynamic loading; BusyBox and apk shared dependencies; shell/PATH
and absolute applet exec; pipes; command substitution; background/wait; nested
shell exit status; shebang argv/environment; bind inheritance and writes; cwd
inheritance; directory traversal; guest absolute symlinks; tar roundtrip;
truncate and apk local database reads. Apk does not access the network or
install packages in this suite.

This is a working minimal command-line rootfs milestone, not complete Linux
container compatibility or hostile-code isolation. Not validated: package
installation, networking, PTY/job control, complete proc/dev semantics,
multithreaded distro workloads, long-running stability and performance.
