TARGET = payload.elf
ELF = payload.elf

ARCH ?= aarch64

ARCH_DIR := arch/$(ARCH)

# Common sources (arch-neutral)
SRC_COMMON := $(addprefix logic/, config.c path_rewrite.c execve_utils.c syscall_hooks.c hook_runtime.c)

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

all: $(TARGET)

$(TARGET): $(ELF)
	@echo "Extracting raw binary..."
	$(OBJCOPY) -O binary -j .text -j .rodata $(ELF) $(TARGET)
	@echo "Payload size: $$(stat -c%s $(TARGET)) bytes"

$(ELF): $(OBJ)
	@echo "Linking payload..."
	# Note: order matters for entry point, but we use -e _start so entry.o doesn't STRICTLY need to be first,
	# but it's good practice.
	$(LD) -shared -Bsymbolic -e _start -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) *.o $(ELF) $(TARGET)
