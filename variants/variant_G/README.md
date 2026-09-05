# variant_G — Hardened tweakable XXTEA-128

A cipher-only redesign that fixes the structural weaknesses of variants
B and C (weak tweak injection, linear schedule, minimum rounds, no
whitening):

1. **32 rounds** instead of the bare minimum 19 (`6 + 52/4`).
2. **Pre/post whitening** — key+tweak material hits the data before round 1
   and after the last round (B/C have none).
3. **Feedback key/tweak schedule** instead of C's linear one: a state
   seeded from the tweak, key words injected per round with rotating word
   selection (after 4 rounds every round key depends on **all** key+tweak
   words), 32-bit additions for nonlinearity, two state words combined per
   round key.
4. **CTR mode with the same shape as A/B/C** — `ctr_xor(data, len, key,
   nonce12)` — so it can drop into the D/E/F authenticated-encryption
   wrappers unchanged.

> ⚠️ **Security status:** experimental, **not a vetted cipher**. Verified
> only by round-trip and avalanche smoke tests (~50% diffusion on
> key/nonce flips, key diffuses from round 1). No cryptanalysis or
> known-answer vectors exist yet. Do not use for production secrets.

## Files

| File             | Purpose                                        |
|------------------|------------------------------------------------|
| `txxtea128_h.h`  | Public API (h = hardened)                      |
| `txxtea128_h.c`  | Implementation (32 rounds, whitening, feedback)|
| `bench_g.c`      | Benchmark: speed, round-trip, avalanche tests  |
| `Makefile`       | Build (Linux / macOS / Windows-MinGW)          |

## Build

```sh
make          # builds bench_g
make run
make clean
```

- Linux / macOS: `make` with `cc`, `clang` or `gcc`.
- Windows: from cmd.exe with MinGW-w64 gcc on PATH —
  `gcc -O2 -Wall -Wextra -o bench_g.exe txxtea128_h.c bench_g.c`

## Run

```sh
./bench_g
```

Measured on macOS (Apple Silicon, clang -O2): ~490 ns per 16-byte block
vs ~210 ns for variant A — roughly 2.3× the cost of the baseline.

## API

```c
#include "txxtea128_h.h"

void txxtea128_h_encrypt_block(uint8_t out[16], const uint8_t in[16],
                               const uint8_t key[16], const uint8_t tweak[16]);
void txxtea128_h_decrypt_block(uint8_t out[16], const uint8_t in[16],
                               const uint8_t key[16], const uint8_t tweak[16]);

void txxtea128_h_ctr_xor(uint8_t *data, size_t len,
                         const uint8_t key[16], const uint8_t nonce12[12]);
```

Same usage rules as the other cipher variants: never reuse a `(key,
nonce)` pair; output length == input length; encrypt == decrypt in CTR.

## How it differs from the other variants

- **vs A:** no tweak, 19 rounds, raw key words.
- **vs B:** tweak only as a final XOR (removable), 19 rounds.
- **vs C:** linear schedule (XOR/rotate), 19 rounds, no whitening.
- **vs D/E/F:** those are *authenticated-encryption wrappers* around
  variant B's cipher; G is the strongest raw cipher core and is meant to
  replace the `txxtea128.c` inside those wrappers.