# variant_B — Tweakable XXTEA-128 (tweak = nonce||counter per block)
#
# Targets: all (default), run, clean
# Works on Linux, macOS and Windows (MSYS2/MinGW).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

TARGET := bench_b
SRCS   := txxtea128.c bench_b.c
HDRS   := txxtea128.h

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

run: all
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o