# Run from this repository root; the experimental backend owns these targets.
.DEFAULT_GOAL := build
.NOTPARALLEL:
PYTHON ?= python3
ALPINE_ARCHIVE ?=
UBUNTU_ARCHIVE ?=
.PHONY: help build check check-alpine check-ubuntu check-fd-runtime bench
help:
	@echo 'make build        Build the AArch64 ELF/PRoot backend'
	@echo 'make check        Build and run core/backend regressions'
	@echo 'make check-fd-runtime Build and test single-task FD tracking experiment'
	@echo 'make check-alpine ALPINE_ARCHIVE=/path/to/rootfs.tar.gz'
	@echo 'make check-ubuntu UBUNTU_ARCHIVE=/path/to/rootfs.tar.gz'
	@echo 'make bench        Native vs loader micro benchmarks (both backends)'
	@echo 'Output: vendor/proot/svc/build/elfloader-proot'
build:
	$(PYTHON) vendor/proot/svc/build_elf.py
check: build
	$(PYTHON) test/fs_policy/run.py
	$(PYTHON) test/fs_policy/vm_model.py
	$(PYTHON) test/fd_table/run.py
	$(PYTHON) test/fd_table/check_clone.py
	$(PYTHON) test/fd_table/check_notify.py
	$(PYTHON) test/fd_table/check_fd_clone.py
	$(PYTHON) test/fd_table/check_payload_abi.py
	$(MAKE) -C vendor/proot/svc check
	$(PYTHON) vendor/proot/port-tests/test_svc.py
	$(PYTHON) vendor/proot/port-tests/test_modify.py
	$(PYTHON) test/fs_policy/xattrs.py --normal
	$(PYTHON) test/fs_policy/access.py --normal
	$(PYTHON) test/fs_policy/ids.py
	$(PYTHON) test/fs_policy/fake_ids.py
	$(PYTHON) test/fs_policy/glue.py
	$(PYTHON) test/fs_policy/interp_links.py
	$(PYTHON) vendor/proot/port-tests/test_inotify.py
	$(PYTHON) vendor/proot/port-tests/test_exec.py
	$(PYTHON) vendor/proot/port-tests/test_auxv.py
	$(PYTHON) test/syscalls/check_dispatch.py
	$(PYTHON) test/syscalls/newer_paths.py
	$(PYTHON) test/syscalls/check_guard.py
	$(PYTHON) test/syscalls/check_runtime.py
	$(PYTHON) -m unittest discover -s test/agent_sandbox -v
	$(PYTHON) -m unittest discover -s test/alpine -p 'test_*.py' -v
# Validate archive arguments before invoking a potentially expensive build.
check-alpine:
	@test -n "$(ALPINE_ARCHIVE)" && test -f "$(ALPINE_ARCHIVE)" || { echo 'Set ALPINE_ARCHIVE to an existing rootfs archive' >&2; exit 2; }
	$(MAKE) build
	$(PYTHON) test/alpine/run.py "$(ALPINE_ARCHIVE)"
check-ubuntu:
	@test -n "$(UBUNTU_ARCHIVE)" && test -f "$(UBUNTU_ARCHIVE)" || { echo 'Set UBUNTU_ARCHIVE to an existing rootfs archive' >&2; exit 2; }
	$(MAKE) build
	$(PYTHON) test/ubuntu/run.py "$(UBUNTU_ARCHIVE)"

check-fd-runtime:
	$(PYTHON) vendor/proot/svc/build_elf.py --fd-experiment
	$(PYTHON) test/fs_policy/transport.py
	$(PYTHON) test/fs_policy/path_mutations.py
	$(PYTHON) test/fs_policy/access.py
	$(PYTHON) test/fs_policy/fd_mutations.py
	$(PYTHON) test/fs_policy/mappings.py
	$(PYTHON) test/fs_policy/madvise_abi.py
	$(PYTHON) test/fs_policy/stdio.py
	$(PYTHON) test/fs_policy/pipes.py
	$(PYTHON) test/fs_policy/revalidate.py
	$(PYTHON) test/fs_policy/xattrs.py
	$(PYTHON) test/fs_policy/ioctls.py
	$(PYTHON) test/fs_policy/fcntls.py
	$(PYTHON) test/fs_policy/async_io.py
	$(PYTHON) test/fs_policy/reads.py
	$(PYTHON) test/fs_policy/agent_launch.py
	$(PYTHON) test/fs_policy/sockets.py
	$(PYTHON) test/fs_policy/local_output.py
	$(PYTHON) test/fs_policy/agent_brew.py
	$(PYTHON) test/fs_policy/threads.py
	$(PYTHON) test/fs_policy/proc_links.py
	$(PYTHON) test/fd_runtime/run.py

bench:
	$(PYTHON) vendor/proot/svc/build_elf.py
	$(PYTHON) vendor/proot/svc/build_elf.py --fd-experiment
	$(PYTHON) test/bench/bench.py
