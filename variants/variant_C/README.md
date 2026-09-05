# variant_C — Tweakable XXTEA-128 with a round-key schedule

Variant B, improved: instead of using raw key words and XORing the tweak
at the end of the mix term, a **per-round key schedule** (`make_rk`)
derives four round keys from the key, the tweak, the round index and the
running `sum`:

```c
rk[i] = k[i] ^ rotl32(t[i], r + i) ^ mix;   // mix = sum + C1*(r+1) + per-index constant
```

The tweak now enters the **key path** and is diffused by the data rounds —
the first real structural improvement over A and B.

> ⚠️ **Security status:** experimental, not a vetted cipher. The schedule
> is still **linear** (only XOR, rotate, constants), each `rk[i]` depends
> on exactly one key word and one tweak word, and variant B's linear
> tweak XOR is kept on top. Variant G is the hardened evolution (nonlinear
> feedback schedule, whitening, 32 rounds).

## Files

| File             | Purpose                                        |
|------------------|------------------------------------------------|
| `txxtea128_rs.h` | Public API (rs = round schedule)               |
| `txxtea128_rs.c` | Implementation (19 rounds + `make_rk`)         |
| `bench_c.c`      | Benchmark: speed, round-trip, avalanche tests  |
| `Makefile`       | Build (Linux / macOS / Windows-MinGW)          |

## Build

```sh
make          # builds bench_c
make run      # builds and runs the benchmark
make clean
```

- Linux / macOS: `make` with `cc`, `clang` or `gcc`.
- Windows: from cmd.exe with MinGW-w64 gcc on PATH —
  `gcc -O2 -Wall -Wextra -o bench_c.exe txxtea128_rs.c bench_c.c`

## Run

```sh
./bench_c
```

## API

```c
#include "txxtea128_rs.h"

void txxtea128_rs_encrypt_block(uint8_t out[16], const uint8_t in[16],
                                const uint8_t key[16], const uint8_t tweak[16]);
void txxtea128_rs_decrypt_block(uint8_t out[16], const uint8_t in[16],
                                const uint8_t key[16], const uint8_t tweak[16]);

void txxtea128_rs_ctr_xor(uint8_t *data, size_t len,
                          const uint8_t key[16], const uint8_t nonce12[12]);
```

Same usage rules as A/B: unique nonce per message, output length == input
length. Encrypt and decrypt share the CTR function.

## How it differs from the other variants

- **vs A:** no tweak support at all.
- **vs B:** tweak only as a final XOR; no schedule.
- **vs D/E/F:** those are authenticated-encryption wrappers around
  variant B's cipher (not C).
- **vs G:** G addresses C's remaining weaknesses — nonlinear feedback
  schedule whose round keys depend on *all* key+tweak words, pre/post
  whitening, and 32 rounds instead of 19.