# Payload: position-independent, no libc; every intercepted syscall runs
# here. GUARDED=1 adds the guarded runtime.
TARGET := payload.bin
ARCH_DIR := arch/aarch64
PROOT_SRC := ../../vendor/proot

SRC := $(addprefix logic/, config.c dispatch.c integrity.c platform.c libc_shim.c hook_runtime.c fake_ids.c \
	clone_notify.c proot_bridge.c proot_exec.c proot_auxv.c) \
	$(addprefix $(ARCH_DIR)/, entry.S raw_syscall.S syscall_disp.c mini_libc.c \
	reentry_guard.c stub.c clone_entry.S)
ifeq ($(GUARDED),1)
SRC += $(addprefix logic/, vm_write_guard.c fs_policy.c fd_runtime.c fd_snapshot.c \
	fd_handoff.c fd_receive.c fd_table.c fd_clone.c fd_registry.c fd_guard.c \
	fd_close_queue.c fd_close_exec.c)
CPPFLAGS += -DGUARDED
endif
OBJ := $(patsubst %.S,%.o,$(SRC:.c=.o)) \
	$(addprefix proot-build/, path_helpers.o canon_core.o resolve_core.o binding_core.o)

CPPFLAGS += -I. -Iinclude -I$(ARCH_DIR) -I$(PROOT_SRC)/src -D_GNU_SOURCE
# Optimized: this code runs on every intercepted syscall. No strict aliasing:
# guest buffers and kernel records are reinterpreted in several places.
CFLAGS := -Wall -O2 -g -fno-strict-aliasing -fPIC -nostdlib -fno-stack-protector -fno-builtin

all: $(TARGET)

$(TARGET): $(OBJ)
	$(LD) -shared --no-undefined -Bsymbolic -e _start -o $@ $(OBJ)

proot-build:
	mkdir -p $@
proot-build/%.o: $(PROOT_SRC)/src/path/%.c | proot-build
	$(CC) $(CPPFLAGS) $(CFLAGS) -DNDEBUG -Djoin_paths=proot_join_paths -MMD -MP -c $< -o $@
-include proot-build/*.d

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
%.o: %.S
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(ARCH_DIR)/entry.o: $(ARCH_DIR)/syscall_nums.h $(ARCH_DIR)/slow_syscalls.inc \
	$(ARCH_DIR)/fd_runtime_syscalls.inc $(ARCH_DIR)/fd_unsupported_syscalls.inc
logic/fd_runtime.o: $(ARCH_DIR)/fd_unsupported_syscalls.inc

clean:
	rm -f $(OBJ) $(TARGET)
	rm -rf proot-build
