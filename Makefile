# variant_G — Hardened tweakable XXTEA-128
# (32 rounds, pre/post whitening, feedback key/tweak schedule)
#
# Targets: all (default: bench_g), run, clean
# Works on Linux, macOS and Windows (MSYS2/MinGW).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

TARGET := bench_g
SRCS   := src/txxtea128_h.c src/bench_g.c
HDRS   := include/crypto_util.h include/txxtea128_h.h

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
