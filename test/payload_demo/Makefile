# 相对 userlandexec/test/payload_demo，工具链配置在 build-hnp/utils
include ../../../../utils/Makefrag

ARCH ?= aarch64

PAYLOAD_BASE := ../../../elf/src/payload
ARCH_DIR := $(PAYLOAD_BASE)/arch/$(ARCH)

LDFLAGS     += -static
override BUILD_DIR := ../../../build
override BIN_DIR   := $(BUILD_DIR)/bin

TARGETS := payload_demo payload_demo_tests

# Pull in payload logic (arch-neutral) + arch-specific mini libc for helpers.
PAYLOAD_COMMON_SRCS := $(addprefix $(PAYLOAD_BASE)/logic/, \
                       config.c log.c execve_utils.c path_rewrite.c syscall_hooks.c hook_runtime.c)
PAYLOAD_ARCH_SRCS := $(addprefix $(ARCH_DIR)/, \
                     mini_libc.c reentry_guard.c raw_syscall.S syscall_disp.c stub.c)
PAYLOAD_SRCS := $(PAYLOAD_COMMON_SRCS) $(PAYLOAD_ARCH_SRCS)

PAYLOAD_INCLUDES := -I$(PAYLOAD_BASE)/include -I$(ARCH_DIR)

.PHONY: all clean

all: $(addprefix $(BIN_DIR)/,$(TARGETS))

$(BIN_DIR)/payload_demo: payload_demo.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) $@

$(BIN_DIR)/payload_demo_tests: payload_demo_tests.c $(PAYLOAD_SRCS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(PAYLOAD_INCLUDES) -o $@ $^
	$(STRIP) $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(addprefix $(BIN_DIR)/,$(TARGETS)) file.lst
