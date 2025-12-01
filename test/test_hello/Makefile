# 相对 userlandexec/test/test_hello，工具链配置在 build-hnp/utils
include ../../../utils/Makefrag

TARGET      ?= test_hello
SRC         := test_hello.c
# 静态链接，便于独立运行
LDFLAGS     += -static
# 将构建产物输出到 userlandexec/build/bin，与 elfloader 等同目录
override BUILD_DIR := ../../build
override BIN_DIR   := $(BUILD_DIR)/bin
TARGET_BIN  := $(BIN_DIR)/$(TARGET)

.PHONY: all clean

all: $(TARGET_BIN)

$(TARGET_BIN): $(SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	$(STRIP) $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	rm -f $(TARGET_BIN) file.lst
