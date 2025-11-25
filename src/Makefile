# make ARCH=i386 SMALL=1 DEBUG=1

ARCH ?= aarch64

ARCHS32 := i386
ARCHS64 := amd64 aarch64
ARCHS := $(ARCHS32) $(ARCHS64)

CFLAGS += -pipe -Wall -O0 -g -Wextra -fPIC -fno-ident -fno-stack-protector -U _FORTIFY_SOURCE
LDFLAGS += -nostartfiles -nodefaultlibs -nostdlib 
LDFLAGS += -pie -e z_start -Wl,-Bsymbolic,--no-undefined,--build-id=none
TARGET := elfloader

PAYLOAD_DIR := payload
PAYLOAD_BIN := $(PAYLOAD_DIR)/payload.bin

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

ifdef DEBUG
  CFLAGS += -O0 -g
  ASFLAGS += -g
else
  CFLAGS += -fvisibility=hidden
  # Disable unwind info to make prog smaller.
  CFLAGS += -Os -fno-asynchronous-unwind-tables -fno-unwind-tables
  LDFLAGS += -s
endif

OBJS := $(patsubst %.c,%.o, $(wildcard *.c))
OBJS += $(patsubst %.S,%.o, $(wildcard $(ARCH)/*.S))

ifdef SMALL
  OBJS := $(filter-out z_printf.%,$(OBJS))
  OBJS := $(filter-out z_err.%,$(OBJS))
  CFLAGS += -DZ_SMALL
endif

.PHONY: clean all

all: $(TARGET) $(PAYLOAD_BIN)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(PAYLOAD_BIN):
	$(MAKE) -C $(PAYLOAD_DIR) ARCH=$(ARCH) CC="$(CC)" LD="$(LD)" OBJCOPY="$(OBJCOPY)"

clean:
	rm -rf *.o $(TARGET) */*.o
	$(MAKE) -C $(PAYLOAD_DIR) clean
