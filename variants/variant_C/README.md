# variant_C — Tweakable XXTEA-128 with a round-key schedule

Variant B with a **per-round key schedule** (`make_rk`). C keeps B's
direct tweak XOR in MX and replaces the raw key words with round keys:

```c
mix = sum + 0x7f4a7c15u * (r + 1); // modulo 2^32
rk[i] = k[i] ^ rotl32(t[i], r + i) ^ mix ^ constant[i];
// constant = {0, 0xa5a5a5a5, 0x3c3c3c3c, 0x5a5a5a5a}
```

For each fixed round this schedule is affine in key/tweak bits: XOR,
rotation and round constants. Each word uses one key word and one tweak
word. The core still runs 19 rounds on a 16-byte block.

> **Research status:** this is a structural change, not evidence of
> improved cryptanalytic security. Correctness tests compare C with a
> separate specification; no security ranking is established.

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

int txxtea128_rs_ctr_xor(uint8_t *data, size_t len,
                          const uint8_t key[16], const uint8_t nonce12[12]);
```

Same usage rules as A/B: unique nonce per message, output length == input
length. Encrypt and decrypt share the CTR function.

## How it differs from the other variants

- **vs A:** no tweak support at all.
- **vs B:** tweak only as a final XOR; no schedule.
- **vs D/E/F:** those are authenticated-encryption wrappers around
  variant B's cipher (not C).
- **vs G:** G changes the structure with a nonlinear feedback
  schedule whose round keys depend on *all* key+tweak words, pre/post
  whitening, and 32 rounds instead of 19.

CTR returns 1 on success, 0 on invalid arguments or counter exhaustion
(more than 2^36 bytes), before changing data. Each call restarts the counter;
do not split messages into repeated calls with the same key/nonce.
The source now includes the shared `../../crypto_util.h` helper; preserve
that relative path when copying a variant, or adapt the include explicitly.
