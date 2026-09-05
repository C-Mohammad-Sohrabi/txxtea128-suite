# Original XXTEA library — build the benchmark
#
#   make          build ./bench  (round-trip + avalanche tests)
#   make run      build and run it
#   make clean    remove the binary

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

bench: src/bench.c src/xxtea.c include/xxtea.h
	$(CC) $(CFLAGS) -Iinclude -o $@ src/bench.c src/xxtea.c

run: bench
	./bench

clean:
	rm -f bench *.o