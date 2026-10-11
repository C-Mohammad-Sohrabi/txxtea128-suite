# variant_A — XXTEA-128 block cipher in CTR mode

The XXTEA cipher from the parent project, reshaped into a **fixed 16-byte
block cipher** (4×32-bit words) with a **16-byte key**, then run in **CTR
mode** to encrypt/decrypt arbitrary-length data.

**This is the baseline variant** — everything else in the `variant_*`
family builds on this design.

> ⚠️ **Security status:** experimental, not a vetted cipher. XXTEA has
> published cryptanalysis (Yarrkov 2010). Do not use for production
> secrets without professional review.

## Files

| File             | Purpose                                        |
|------------------|------------------------------------------------|
| `xxtea128.h`     | Public API                                     |
| `xxtea128.c`     | Block cipher + CTR implementation              |
| `bench_a.c`      | Benchmark: speed, round-trip, avalanche tests  |
| `Makefile`       | Build (Linux / macOS / Windows-MinGW)          |

## Build

```sh
make          # builds bench_a
make run      # builds and runs the benchmark
make clean
```

- Linux / macOS: `make` with any C compiler (`cc`, `clang`, `gcc`).
- Windows: from cmd.exe with MinGW-w64 gcc on PATH —
  `gcc -O2 -Wall -Wextra -o bench_a.exe xxtea128.c bench_a.c`

## Run

```sh
./bench_a
```

Output lines report, per message size: encrypt/decrypt ns/op, round-trip
`ok` flag, and avalanche percentages for plaintext / nonce / key bit flips.

## API

```c
#include "xxtea128.h"

// Encrypt/decrypt one 16-byte block (key must be 16 bytes).
void xxtea128_encrypt_block(uint8_t out[16], const uint8_t in[16],
                            const uint8_t key[16]);
void xxtea128_decrypt_block(uint8_t out[16], const uint8_t in[16],
                            const uint8_t key[16]);

// CTR mode: XORs data in place with the keystream.
// nonce12 = 12-byte nonce; a 32-bit counter is appended per block.
// Encrypt and decrypt are the same call.
int xxtea128_ctr_xor(uint8_t *data, size_t len,
                      const uint8_t key[16], const uint8_t nonce12[12]);
```

**Usage notes:**

- Never reuse a `(key, nonce)` pair for two different messages — CTR is a
  stream mode; reuse leaks plaintext.
- The ciphertext length equals the plaintext length.

## How it differs from the other variants

- **vs B:** B adds a tweak (per-block `nonce||counter`) — A has no tweak.
- **vs C:** C adds a per-round key schedule — A uses key words directly.
- **vs D/E/F:** those wrap the cipher in authenticated encryption
  (Encrypt-then-MAC + HMAC-SHA256).
- **vs G:** G is the hardened redesign (32 rounds, whitening, feedback
  schedule) — A is the minimal baseline.

CTR returns 1 on success, 0 on invalid arguments or counter exhaustion
(more than 2^36 bytes), before changing data. Each call restarts the counter;
do not split messages into repeated calls with the same key/nonce.
The source now includes the shared `../../crypto_util.h` helper; preserve
that relative path when copying a variant, or adapt the include explicitly.
