# variant_B — Tweakable XXTEA-128 (tweak = nonce||counter per block)
#
# Targets: all (default), run, clean
# Works on Linux, macOS and Windows (MSYS2/MinGW).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

TARGET := bench_b
SRCS   := src/txxtea128.c src/bench_b.c
HDRS   := include/crypto_util.h include/txxtea128.h

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
