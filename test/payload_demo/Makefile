# 相对 userlandexec/test/payload_demo，工具链配置在 build-hnp/utils
include ../../../utils/Makefrag

LDFLAGS     += -static
override BUILD_DIR := ../../build
override BIN_DIR   := $(BUILD_DIR)/bin

TARGETS := payload_demo payload_demo_tests

PAYLOAD_SRCS := ../../elf/src/payload/execve_utils.c \
                ../../elf/src/payload/path_rewrite.c \
                ../../elf/src/payload/config.c \
                ../../elf/src/payload/mini_libc.c

.PHONY: all clean

all: $(addprefix $(BIN_DIR)/,$(TARGETS))

$(BIN_DIR)/payload_demo: payload_demo.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) $@

$(BIN_DIR)/payload_demo_tests: payload_demo_tests.c $(PAYLOAD_SRCS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -I../../elf/src/payload -o $@ $^
	$(STRIP) $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(addprefix $(BIN_DIR)/,$(TARGETS)) file.lst
