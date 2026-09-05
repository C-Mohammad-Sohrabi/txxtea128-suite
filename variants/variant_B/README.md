# variant_B — Tweakable XXTEA-128

Variant A extended with a **16-byte tweak**. In CTR mode the per-block
tweak is `nonce(12) || counter(4)`, so every block is encrypted under a
different "context".

> ⚠️ **Security status:** experimental, not a vetted cipher. The tweak is
> injected only as a final XOR in the mixing term (`base ^ t[p & 3]`), so
> it is **not diffused** through the cipher's rotations/additions — an
> attacker who controls tweaks can largely XOR it out and reduce the
> cipher to untweaked variant A. See variant C for a stronger tweak
> design and variant G for the hardened design.

## Files

| File             | Purpose                                        |
|------------------|------------------------------------------------|
| `txxtea128.h`    | Public API (tweakable block cipher + CTR)      |
| `txxtea128.c`    | Implementation (19 rounds, tweak XOR injection)|
| `bench_b.c`      | Benchmark: speed, round-trip, avalanche tests  |
| `Makefile`       | Build (Linux / macOS / Windows-MinGW)          |

## Build

```sh
make          # builds bench_b
make run      # builds and runs the benchmark
make clean
```

- Linux / macOS: `make` with `cc`, `clang` or `gcc`.
- Windows: from cmd.exe with MinGW-w64 gcc on PATH —
  `gcc -O2 -Wall -Wextra -o bench_b.exe txxtea128.c bench_b.c`

## Run

```sh
./bench_b
```

## API

```c
#include "txxtea128.h"

// One 16-byte block; tweak is 16 bytes.
void txxtea128_encrypt_block(uint8_t out[16], const uint8_t in[16],
                             const uint8_t key[16], const uint8_t tweak[16]);
void txxtea128_decrypt_block(uint8_t out[16], const uint8_t in[16],
                             const uint8_t key[16], const uint8_t tweak[16]);

// CTR mode; per-block tweak = nonce12 || counter_le32.
void txxtea128_ctr_xor(uint8_t *data, size_t len,
                       const uint8_t key[16], const uint8_t nonce12[12]);
```

**Usage notes:** same as variant A — never reuse a `(key, nonce)` pair;
ciphertext length equals plaintext length.

## How it differs from the other variants

- **vs A:** adds the tweak parameter (weak final-XOR injection).
- **vs C:** C replaces the raw tweak XOR with a per-round key schedule
  derived from key + tweak + round + sum.
- **vs D/E/F:** those embed this exact cipher (`txxtea128.c` is copied
  byte-for-byte into variant_D and variant_F) inside an authenticated
  encryption wrapper.
- **vs G:** G keeps the tweak concept but diffuses it via a feedback
  schedule, adds whitening, and raises the round count to 32.