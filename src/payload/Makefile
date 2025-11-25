TARGET = payload.elf
ELF = payload.elf

# Update Source List: Added syscall_disp.c and raw_syscall.S
SRC = entry.S raw_syscall.S syscall_disp.c mini_libc.c
OBJ = $(SRC:.c=.o)
OBJ := $(OBJ:.S=.o)
CFLAGS = -Wall -O0 -g -fPIC -nostdlib -fno-stack-protector -fno-builtin -Isrc

all: $(TARGET)

$(TARGET): $(ELF)
	@echo "Extracting raw binary..."
	$(OBJCOPY) -O binary -j .text -j .rodata $(ELF) $(TARGET)
	@echo "Payload size: $$(stat -c%s $(TARGET)) bytes"

$(ELF): $(OBJ)
	@echo "Linking payload..."
	# Note: order matters for entry point, but we use -e _start so entry.o doesn't STRICTLY need to be first, 
	# but it's good practice.
	$(LD) -shared -Bsymbolic -e _start -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(ELF) $(TARGET)