# Single-task FD runtime experiment

Run from the repository root:

```sh
make check-fd-runtime
vendor/proot/svc/build/elfloader-proot-fd-experiment --mode compat -- /path/to/program
```

This builds a separate executable and manifest. Normal `make build`/`make check`
continue to produce `elfloader-proot` with the existing behavior. Both builds
share intermediate object paths, so do not build them concurrently. The last
build also determines `src/elfloader`; prefer the named snapshots above.

The experimental payload initializes a single-task registry on first slow call,
tracks up to 128 descriptors from openat, dup, dup3, F_DUPFD/F_DUPFD_CLOEXEC and
F_SETFD, and routes close through reserved outcome bookkeeping. Inherited FDs
start untracked; dup of one remains unknown provenance. All open provenance is
UNKNOWN: there is no readonly/default-deny permission policy in this experiment.

Clone, exec, close_range, unshare and selected alternate FD creation/transfer
interfaces return ENOSYS. Same-task nested slow calls return EDEADLK, other task
identities are refused, and no guard is held across blocking syscalls. Uncertain
close outcomes remain pending (no automatic provenance withdrawal). This is a
single-task debugging mode, not general shell/container compatibility, complete
FD interception, or an adversarial isolation boundary. Existing raw-entry/path
race limitations still apply. Do not enable it as an agent sandbox yet.

For validation only, prctl(PR_ELF_FD_QUERY=0x46445452, selector, fd) returns:

- selector 0: tracked record count;
- selector 1: descriptor generation;
- selector 2: open-description identity;
- selector 3: CLOEXEC bit.

Missing records return ENOENT. This diagnostic interface is absent from the
normal payload and exposes no permission grants. It is not a stable public ABI.

The libc-free guest runs through the actual loader/dispatcher, reads a fixture
file, checks duplication identities and descriptor flags, closes descriptors,
and checks failure and capacity behavior. It links none of the FD metadata
modules itself. Optional existing Alpine/Ubuntu fixtures also run their cat
programs; missing fixtures are reported as skipped, not counted as passes.
