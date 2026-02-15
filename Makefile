CC = x86_64-w64-mingw32-g++
CFLAGS = -I . -Os -fno-asynchronous-unwind-tables -nostdlib -fno-exceptions -fno-rtti -fno-leading-underscore -fno-stack-protector
TARGET = vault_dump.x64.o
SOURCE = bof_vault.cpp

all:
	$(CC) -o $(TARGET) -c $(SOURCE) $(CFLAGS)

clean:
	rm -f $(TARGET)
