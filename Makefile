CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra
PYTHON ?= python3
.PHONY: all test test-sanitize run clean
all: bench example/xxtea_example
bench: src/bench.c src/xxtea.c include/xxtea.h include/crypto_util.h
	$(CC) $(CFLAGS) -Iinclude -o $@ src/bench.c src/xxtea.c
example/xxtea_example: example/test.c example/base64.c example/base64.h src/xxtea.c include/xxtea.h include/crypto_util.h
	$(CC) $(CFLAGS) -I. -Iinclude -o $@ example/test.c example/base64.c src/xxtea.c
run: all
	./example/xxtea_example
	./bench
test:
	$(PYTHON) tests/run_tests.py
test-sanitize:
	$(PYTHON) tests/run_tests.py --sanitize
clean:
	rm -f bench example/xxtea_example *.o
