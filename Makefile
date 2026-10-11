# variant_C — Tweakable XXTEA-128 with a per-round key schedule
#
# Targets: all (default), run, clean
# Works on Linux, macOS and Windows (MSYS2/MinGW).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

TARGET := bench_c
SRCS   := src/txxtea128_rs.c src/bench_c.c
HDRS   := include/crypto_util.h include/txxtea128_rs.h

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRCS)

run: all
	./$(TARGET)

clean:
	rm -f $(TARGET) *.o

PYTHON ?= python3
.PHONY: all run clean test test-sanitize
test:
	$(PYTHON) tests/run_tests.py
test-sanitize:
	$(PYTHON) tests/run_tests.py --sanitize
