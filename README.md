# Variant G · XXTEA-128 · feedback schedule and whitening

**Standalone tag `G`** · C implementation · Research project

```sh
git clone --branch G --single-branch https://github.com/C-Mohammad-Sohrabi/txxtea128-suite.git variant-G
cd variant-G
make
make test
make test-sanitize
```

This checkout includes only variant G's runtime sources and its local
helpers. No sibling project or original-library checkout is needed. Building
requires Make and a C11 compiler; tests also need Python 3. ASan/UBSan requires
a supporting compiler. OpenSSL is not required.


An experimental cipher-only redesign of the B/C branch. The changes below
are design choices, not demonstrated fixes for cryptanalytic attacks:

1. **32 rounds** instead of the original n=4 count of 19 (`6 + 52/4`).
2. **Pre/post whitening** — key+tweak material hits the data before round 1
   and after the last round (B/C have none).
3. **Feedback key/tweak schedule** instead of C's linear one: a state
   seeded from the tweak, key words injected per round with rotating word
   selection (after 4 rounds every round key depends on **all** key+tweak
   words), 32-bit additions for nonlinearity, two state words combined per
   round key.
4. **CTR mode with the same shape as A/B/C** — `ctr_xor(data, len, key,
   nonce12)` — integration with D/E/F requires adapting function names/headers
   and introducing a distinct envelope identifier; ciphertext changes.

> ⚠️ **Security status:** experimental, **not a vetted cipher**. Verified
> by the independent reference, inverse/CTR tests, frozen project vectors,
> and ASan/UBSan tests in `tests/`. These are correctness checks,
> not a cryptanalytic security evaluation. Do not use for production secrets.

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

Benchmark timings depend on the compiler, machine and cleanup work. Run
`make run` on the target system; no fixed performance ratio is promised.

## API

```c
#include "txxtea128_h.h"

void txxtea128_h_encrypt_block(uint8_t out[16], const uint8_t in[16],
                               const uint8_t key[16], const uint8_t tweak[16]);
void txxtea128_h_decrypt_block(uint8_t out[16], const uint8_t in[16],
                               const uint8_t key[16], const uint8_t tweak[16]);

int txxtea128_h_ctr_xor(uint8_t *data, size_t len,
                         const uint8_t key[16], const uint8_t nonce12[12]);
```

Same usage rules as the other cipher variants: never reuse a `(key,
nonce)` pair; output length == input length; encrypt == decrypt in CTR.

## How it differs from the other variants

- **vs A:** no tweak, 19 rounds, raw key words.
- **vs B:** tweak XORed into each MX update, 19 rounds.
- **vs C:** linear schedule (XOR/rotate), 19 rounds, no whitening.
- **vs D/E/F:** those are *authenticated-encryption wrappers* around
  variant B's cipher; G is a separate unvetted core and is not currently
  used by those wrappers. Relative security has not been established.

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
