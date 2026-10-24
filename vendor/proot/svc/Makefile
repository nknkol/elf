# Path-only library: no ptrace, talloc, libc link, or target process startup.
CC = clang
AR = llvm-ar
NM = llvm-nm
CPPFLAGS += -D_GNU_SOURCE -I../src
CFLAGS += -std=c11 -O2 -Wall -Wextra -Werror -fPIC -ffreestanding -fno-builtin -fno-stack-protector
NAMES = path_helpers canon_core resolve_core binding_core
OBJECTS = $(addprefix build/,$(addsuffix .o,$(NAMES)))
.PHONY: all clean check
all: build/libproot_path.a build/undefined-symbols.txt
build:
	mkdir -p $@
build/%.o: ../src/path/%.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@
build/libproot_path.a: $(OBJECTS)
	$(AR) rcs $@ $^
build/path-combined.o: $(OBJECTS)
	$(CC) -nostdlib -r $^ -o $@
build/undefined-symbols.txt: build/path-combined.o
	$(NM) --undefined-only $< > $@
check:
	sh ../port-tests/check.sh
clean:
	rm -rf build
-include $(OBJECTS:.o=.d)

.PHONY: bridge check-bridge
bridge:
	python3 build_elf.py
check-bridge:
	python3 ../port-tests/test_svc.py
