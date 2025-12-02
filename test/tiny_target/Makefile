# userlandexec/test_hello/Makefile

include ../../../../utils/Makefrag

TARGET      ?= tiny_target
SRC         := tiny_target.S
override BUILD_DIR := ../../../build
override BIN_DIR   := $(BUILD_DIR)/bin
TARGET_BIN  := $(BIN_DIR)/$(TARGET)

# 关键修改：添加 -nostdlib -static -e _start
# 这会强制生成纯净的裸机二进制文件，不包含 libc
LDFLAGS_TINY := -nostdlib -static -e _start

.PHONY: all clean

all: $(TARGET_BIN)

$(TARGET_BIN): $(SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS_TINY) -o $@ $<
	$(STRIP) $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(TARGET_BIN) file.lst