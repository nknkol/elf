# Run from this repository root; the experimental backend owns these targets.
.DEFAULT_GOAL := build
.NOTPARALLEL:
PYTHON ?= python3
ALPINE_ARCHIVE ?=
UBUNTU_ARCHIVE ?=
.PHONY: help build check check-alpine check-ubuntu
help:
	@echo 'make build        Build the AArch64 ELF/PRoot backend'
	@echo 'make check        Build and run core/backend regressions'
	@echo 'make check-alpine ALPINE_ARCHIVE=/path/to/rootfs.tar.gz'
	@echo 'make check-ubuntu UBUNTU_ARCHIVE=/path/to/rootfs.tar.gz'
	@echo 'Output: vendor/proot/svc/build/elfloader-proot'
build:
	$(PYTHON) vendor/proot/svc/build_elf.py
check: build
	$(PYTHON) test/fd_table/run.py
	$(PYTHON) test/fd_table/check_clone.py
	$(MAKE) -C vendor/proot/svc check
	$(PYTHON) vendor/proot/port-tests/test_svc.py
	$(PYTHON) vendor/proot/port-tests/test_modify.py
	$(PYTHON) vendor/proot/port-tests/test_exec.py
	$(PYTHON) vendor/proot/port-tests/test_auxv.py
	$(PYTHON) test/syscalls/check_dispatch.py
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
