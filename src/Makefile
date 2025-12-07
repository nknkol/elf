# make ARCH=i386 SMALL=1 DEBUG=1

ARCH ?= aarch64

ARCHS32 := i386
ARCHS64 := amd64 aarch64
ARCHS := $(ARCHS32) $(ARCHS64)

ARCH_DIR       := arch/$(ARCH)
PAYLOAD_ARCH_DIR := payload/arch/$(ARCH)

CFLAGS += -pipe -Wall -O0 -g -Wextra -fPIC -fno-ident -fno-stack-protector -U _FORTIFY_SOURCE
# Include paths for loader and payload headers; keep in CPPFLAGS to survive CFLAGS overrides
CPPFLAGS += -I$(CURDIR) -I$(CURDIR)/include -I$(CURDIR)/payload/include
CPPFLAGS += -I. -Iinclude -Ipayload/include
PAYLOAD_CFLAGS :=
LDFLAGS += -nostartfiles -nodefaultlibs -nostdlib 
LDFLAGS += -pie -e z_start -Wl,-Bsymbolic,--no-undefined,--build-id=none
TARGET := elfloader

PAYLOAD_DIR := payload
PAYLOAD_BIN := $(PAYLOAD_DIR)/payload.bin

TINY_INIT_DIR := tiny-init
TINY_INIT_BIN := $(TINY_INIT_DIR)/tiny-init
TINY_INIT_OBJ := $(TINY_INIT_DIR)/tiny-init.o

ifeq ($(ARCH),aarch64)
  TINY_INIT_OBJFMT := elf64-littleaarch64
  TINY_INIT_ARCH := aarch64
else ifeq ($(ARCH),amd64)
  TINY_INIT_OBJFMT := elf64-x86-64
  TINY_INIT_ARCH := i386:x86-64
else ifeq ($(ARCH),i386)
  TINY_INIT_OBJFMT := elf32-i386
  TINY_INIT_ARCH := i386
endif

ifeq "$(filter $(ARCH),$(ARCHS))" ""
  $(error ARCH='$(ARCH)' is not supported)
endif

ifeq "$(filter $(ARCH),$(ARCHS32))" "$(ARCH)"
  CFLAGS += -m32 -DELFCLASS=ELFCLASS32
  ASFLAGS += -m32
  LDFLAGS += -m32
else
  CFLAGS += -DELFCLASS=ELFCLASS64
endif

ifdef DEFAULT_CONFIG_PATH
  CFLAGS += -DCONFIG_DEFAULT_CONFIG_PATH=\"$(DEFAULT_CONFIG_PATH)\"
  PAYLOAD_CFLAGS += -DCONFIG_DEFAULT_CONFIG_PATH=\"$(DEFAULT_CONFIG_PATH)\"
endif

ifdef DEBUG
  CFLAGS += -O0 -g
  ASFLAGS += -g
else
  CFLAGS += -fvisibility=hidden
  # Disable unwind info to make prog smaller.
  CFLAGS += -Os -fno-asynchronous-unwind-tables -fno-unwind-tables
  LDFLAGS += -s
endif

# Loader objects: core + utils + arch-specific helpers/stubs/hooks
SRCS := $(wildcard *.c)
SRCS += $(wildcard utils/*.c)
SRCS += $(wildcard $(ARCH_DIR)/*.c)
SRCS += $(wildcard $(PAYLOAD_ARCH_DIR)/hook.c) $(wildcard $(PAYLOAD_ARCH_DIR)/stub.c)

ASRCS := $(wildcard $(ARCH_DIR)/*.S)

OBJS := $(SRCS:.c=.o) $(ASRCS:.S=.o) $(TINY_INIT_OBJ)

ifdef SMALL
  OBJS := $(filter-out %/z_printf.o,$(OBJS))
  OBJS := $(filter-out %/z_err.o,$(OBJS))
  CFLAGS += -DZ_SMALL
endif

.PHONY: clean all

all: $(TARGET) $(PAYLOAD_BIN)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(PAYLOAD_BIN):
	$(MAKE) -C $(PAYLOAD_DIR) ARCH=$(ARCH) CC="$(CC)" LD="$(LD)" OBJCOPY="$(OBJCOPY)" EXTRA_CFLAGS="$(PAYLOAD_CFLAGS)"

$(TINY_INIT_BIN):
	$(MAKE) -C $(TINY_INIT_DIR) CC="$(CC)"

$(TINY_INIT_OBJ): $(TINY_INIT_BIN)
ifeq ($(strip $(TINY_INIT_OBJFMT)),)
	$(error Unsupported ARCH $(ARCH) for tiny-init embedding)
endif
	$(OBJCOPY) -I binary -O $(TINY_INIT_OBJFMT) -B $(TINY_INIT_ARCH) $(TINY_INIT_BIN) $(TINY_INIT_OBJ)

clean:
	rm -rf *.o $(TARGET) */*.o */*/*.o
	$(MAKE) -C $(PAYLOAD_DIR) clean
	$(MAKE) -C $(TINY_INIT_DIR) clean
