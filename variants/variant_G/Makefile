# variant_G — Hardened tweakable XXTEA-128
# (32 rounds, pre/post whitening, feedback key/tweak schedule)
#
# Targets: all (default: bench_g), run, clean
# Works on Linux, macOS and Windows (MSYS2/MinGW).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

TARGET := bench_g
SRCS   := txxtea128_h.c bench_g.c
HDRS   := ../../crypto_util.h txxtea128_h.h

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

run: all
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o