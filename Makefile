# Run from the repository root. Outputs: build/elfloader, build/elfloader-guarded.
.DEFAULT_GOAL := build
.NOTPARALLEL:
PYTHON ?= python3
ALPINE_ARCHIVE ?=
UBUNTU_ARCHIVE ?=
.PHONY: help build check check-alpine check-ubuntu check-guarded bench
help:
	@echo 'make build          Build build/elfloader and build/elfloader-guarded'
	@echo 'make check          Core regressions (both builds)'
	@echo 'make check-guarded  Guarded runtime regressions'
	@echo 'make check-alpine ALPINE_ARCHIVE=/path/to/rootfs.tar.gz'
	@echo 'make check-ubuntu UBUNTU_ARCHIVE=/path/to/rootfs.tar.gz'
	@echo 'make bench          Native vs loader micro benchmarks (both builds)'
build:
	$(PYTHON) tools/build.py
	$(PYTHON) tools/build.py --guarded
check: build
	$(PYTHON) test/fs_policy/run.py
	$(PYTHON) test/fs_policy/vm_model.py
	$(PYTHON) test/fd_table/run.py
	$(PYTHON) test/fd_table/check_clone.py
	$(PYTHON) test/fd_table/check_notify.py
	$(PYTHON) test/fd_table/check_fd_clone.py
	$(PYTHON) test/fd_table/check_payload_abi.py
	$(PYTHON) test/proot/test_paths.py
	$(PYTHON) test/proot/test_svc.py
	$(PYTHON) test/proot/test_modify.py
	$(PYTHON) test/fs_policy/xattrs.py --normal
	$(PYTHON) test/fs_policy/access.py --normal
	$(PYTHON) test/fs_policy/ids.py
	$(PYTHON) test/fs_policy/fake_ids.py
	$(PYTHON) test/fs_policy/link_copy.py
	$(PYTHON) test/fs_policy/process_tree.py
	$(PYTHON) test/fs_policy/quiet.py
	$(PYTHON) test/fs_policy/small_stack.py
	$(PYTHON) test/fs_policy/stub_islands.py
	$(PYTHON) test/fs_policy/elf_layout.py
	$(PYTHON) test/fs_policy/guest_signals.py
	$(PYTHON) test/fs_policy/backstop.py
	$(PYTHON) test/fs_policy/isolate.py
	$(PYTHON) test/fs_policy/glue.py
	$(PYTHON) test/fs_policy/interp_links.py
	$(PYTHON) test/proot/test_inotify.py
	$(PYTHON) test/proot/test_exec.py
	$(PYTHON) test/proot/test_auxv.py
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

check-guarded: build
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
	$(PYTHON) test/fs_policy/dup_race.py
	$(PYTHON) test/fs_policy/fd_swap.py
	$(PYTHON) test/fs_policy/case_alias.py
	$(PYTHON) test/fs_policy/path_race.py
	$(PYTHON) test/fs_policy/fexecve_guard.py
	$(PYTHON) test/fs_policy/proc_links.py
	$(PYTHON) test/fd_runtime/run.py

bench: build
	$(PYTHON) test/bench/bench.py
