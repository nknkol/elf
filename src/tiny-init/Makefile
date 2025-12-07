TARGET := tiny-init
CC ?= cc

# 避免继承上层 CFLAGS/LDFLAGS，强制使用正常 libc + 静态链接
override CFLAGS := -Wall -O2 -static
override LDFLAGS :=

.PHONY: all clean

all: $(TARGET)

$(TARGET): main.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

main.o: main.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) main.o
