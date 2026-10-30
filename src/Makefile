# AArch64 loader with the embedded payload. Built by tools/build.py;
# GUARDED=1 selects the guarded runtime.
TARGET := elfloader

CPPFLAGS += -I$(CURDIR)/include -I$(CURDIR)/loader -I$(CURDIR)/payload/include \
	-I$(CURDIR)/payload/arch/aarch64 -DELFCLASS=ELFCLASS64
ifeq ($(GUARDED),1)
CPPFLAGS += -DGUARDED
endif
CFLAGS += -pipe -Wall -Wextra -Os -fno-ident -fno-stack-protector -U_FORTIFY_SOURCE \
	-fvisibility=hidden -fno-asynchronous-unwind-tables -fno-unwind-tables
LDFLAGS += -nostartfiles -nodefaultlibs -nostdlib -s

PAYLOAD_BIN := payload/payload.bin
PAYLOAD_OBJ := payload/payload_embed.o

SRCS := $(wildcard loader/*.c) $(wildcard utils/*.c) arch/aarch64/arch.c \
	payload/arch/aarch64/stub.c
ASRCS := $(wildcard arch/aarch64/*.S)
OBJS := $(SRCS:.c=.o) $(ASRCS:.S=.o) $(PAYLOAD_OBJ)

.PHONY: all clean $(PAYLOAD_BIN)
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(PAYLOAD_BIN):
	$(MAKE) -C payload CC="$(CC)" LD="$(LD)" GUARDED=$(GUARDED)

$(PAYLOAD_OBJ): $(PAYLOAD_BIN)
	$(OBJCOPY) -I binary -O elf64-littleaarch64 -B aarch64 $< $@

clean:
	rm -f $(TARGET) $(OBJS)
	$(MAKE) -C payload clean
