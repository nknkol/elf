.DEFAULT_GOAL := all
TARGET = payload.bin

ARCH ?= aarch64

ARCH_DIR := arch/$(ARCH)

# Common sources (arch-neutral)
SRC_COMMON := $(addprefix logic/, config.c log.c utils.c radix_tree.c vfs_core.c path_rewrite.c execve_utils.c exec_handler.c syscall_hooks.c hook_runtime.c)

# Arch-specific sources
SRC_ARCH_aarch64 := $(addprefix $(ARCH_DIR)/, entry.S raw_syscall.S syscall_disp.c mini_libc.c reentry_guard.c stub.c)

SRC_ARCH = $(SRC_ARCH_$(ARCH))

ifeq ($(strip $(SRC_ARCH)),)
  $(error ARCH '$(ARCH)' is not supported in payload)
endif

SRC = $(SRC_COMMON) $(SRC_ARCH)
OBJ = $(SRC:.c=.o)
OBJ := $(OBJ:.S=.o)

INCLUDES := -I. -Isrc -Iinclude -I$(ARCH_DIR)

# Payload 默认用极简运行时：裸 syscall + mini_libc.c，不链接 musl；保留 -nostdlib。
CFLAGS = -Wall -O0 -g -fPIC -nostdlib -fno-stack-protector -fno-builtin
CPPFLAGS += $(INCLUDES)
CFLAGS += $(EXTRA_CFLAGS)

ifeq ($(FD_EXPERIMENT),1)
ifneq ($(PROOT_PATH),1)
$(error FD_EXPERIMENT requires PROOT_PATH=1)
endif
CPPFLAGS += -DFD_EXPERIMENT
OBJ += $(addprefix logic/,fd_experiment.o fd_table.o fd_clone.o fd_registry.o fd_guard.o fd_close_queue.o fd_close_exec.o)
endif

# Explicit opt-in while only a subset of file syscalls is migrated.
ifeq ($(PROOT_PATH),1)
PROOT_SRC ?= ../../vendor/proot
CPPFLAGS += -DPROOT_PATH -D_GNU_SOURCE -I$(PROOT_SRC)/src
OBJ += logic/clone_notify.o $(ARCH_DIR)/clone_entry.o logic/proot_bridge.o logic/proot_exec.o logic/proot_auxv.o $(addprefix proot-build/,path_helpers.o canon_core.o resolve_core.o binding_core.o runtime.o)
proot-build:
	mkdir -p $@
proot-build/%.o: $(PROOT_SRC)/src/path/%.c | proot-build
	$(CC) $(CPPFLAGS) $(CFLAGS) -DNDEBUG -Djoin_paths=proot_join_paths -MMD -MP -c $< -o $@
proot-build/runtime.o: $(PROOT_SRC)/svc/runtime.c | proot-build
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@
-include proot-build/*.d
endif

$(ARCH_DIR)/entry.o: $(ARCH_DIR)/syscall_nums.h $(ARCH_DIR)/slow_syscalls.inc $(ARCH_DIR)/fd_experiment_syscalls.inc

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "Linking payload..."
	# Note: order matters for entry point, but we use -e _start so entry.o doesn't STRICTLY need to be first,
	# but it's good practice.
	$(LD) -shared --no-undefined -Bsymbolic -e _start -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) *.o $(TARGET)
	rm -rf proot-build
