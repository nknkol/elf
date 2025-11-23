TARGET = payload.bin
ELF = payload.elf

SRC = entry.S payload.c mini_libc.c
OBJ = $(SRC:.c=.o)
OBJ := $(OBJ:.S=.o)

CC = aarch64-linux-gnu-gcc
LD = aarch64-linux-gnu-ld
OBJCOPY = aarch64-linux-gnu-objcopy
CFLAGS = -Wall -O2 -fPIC -nostdlib -fno-stack-protector -fno-builtin -Isrc

all: $(TARGET)

$(TARGET): $(ELF)
	@echo "Extracting raw binary..."
	$(OBJCOPY) -O binary -j .text -j .rodata $(ELF) $(TARGET)
	@echo "Payload size: $$(stat -c%s $(TARGET)) bytes"

$(ELF): $(OBJ)
	@echo "Linking payload..."
	$(LD) -e _start -Ttext 0x0 -o $(ELF) entry.o payload.o mini_libc.o

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(ELF) $(TARGET)