
include ../../../utils/Makefrag

# 在此列出需要构建的测试程序子目录（与生成的可执行同名）
# 新增测试时，添加子目录名即可：TESTS := test_hello tiny_target ...
TESTS ?= test_hello tiny_target payload_demo usernamespace mmap_test syscall_tester

# 强制将生成目录指向 userlandexec/build，避免污染 test 子目录
override BUILD_DIR := ../../build
override BIN_DIR := $(BUILD_DIR)/bin

.PHONY: all clean $(TESTS)

all: $(addprefix $(BIN_DIR)/,$(TESTS))

# 统一在上级 build/bin 下生成可执行，实际编译在各自子目录完成
$(BIN_DIR)/%: | $(BIN_DIR)
	$(MAKE) -C $* BUILD_DIR=$(abspath $(BUILD_DIR)) BIN_DIR=$(abspath $(BIN_DIR)) TARGET=$*

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

clean:
	@for t in $(TESTS); do \
		$(MAKE) -C $$t clean BUILD_DIR=$(abspath $(BUILD_DIR)) BIN_DIR=$(abspath $(BIN_DIR)) TARGET=$$t; \
	done
