# variant_C — Tweakable XXTEA-128 with a per-round key schedule
#
# Targets: all (default), run, clean
# Works on Linux, macOS and Windows (MSYS2/MinGW).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

TARGET := bench_c
SRCS   := txxtea128_rs.c bench_c.c
HDRS   := ../../crypto_util.h txxtea128_rs.h

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

run: all
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o