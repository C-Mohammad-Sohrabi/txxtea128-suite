# variant_A — XXTEA-128 as a fixed 16-byte block cipher, run in CTR mode
#
# Targets: all (default), run, clean
# Works on Linux, macOS and Windows (MSYS2/MinGW).

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

TARGET := bench_a
SRCS   := src/xxtea128.c src/bench_a.c
HDRS   := include/crypto_util.h include/xxtea128.h

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
