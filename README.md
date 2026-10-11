# Variant A · XXTEA-128 · fixed block and CTR

**Standalone tag `A`** · C implementation · Research project

```sh
git clone --branch A --single-branch https://github.com/C-Mohammad-Sohrabi/txxtea128-suite.git variant-A
cd variant-A
make
make test
make test-sanitize
```

This checkout includes only variant A's runtime sources and its local
helpers. No sibling project or original-library checkout is needed. Building
requires Make and a C11 compiler; tests also need Python 3. ASan/UBSan requires
a supporting compiler. OpenSSL is not required.


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
The required `crypto_util.h` helper is included in this project root.


## Standalone CMake build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix ./build/install
```

## Verification and API contracts

`tests/` compares the C implementation with an independent Python reference
and frozen project vectors. `make test-sanitize` adds instrumented C execution.
These are functional tests, not official third-party vectors or a security
proof. Native Windows, 32-bit and big-endian execution are not claimed.

Stream calls return 1/0 and reject invalid input before writing. Every stream
call restarts the counter: never reuse a key/nonce pair, including by splitting
one message across calls. Low-level block calls require valid 16-byte buffers
and support exact in-place operation. Other partial overlap is unsupported.

See [CHANGELOG.md](CHANGELOG.md) for changes and migration notes.

## Explore the family

[Original XXTEA (main)](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/main) · [A](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/A) · [B](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/B) · [C](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/C) · [D](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/D) · [E](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/E) · [F](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/F) · [G](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/G)

Each A–G tag is a standalone source tree. The letters identify research
variants, not security levels. [archive/suite](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/archive/suite)
keeps the reviewed aggregate project and interoperability tests. The old
`v0.1.0`–`v0.9.0` tags remain unchanged historical milestones.

## License

See [LICENSE.md](LICENSE.md); original source attributions are retained.
