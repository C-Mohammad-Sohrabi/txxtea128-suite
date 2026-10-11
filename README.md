# Variant E · Encrypt-then-MAC · reusable context

**Standalone tag `E`** · C implementation · Research project

```sh
git clone --branch E --single-branch https://github.com/C-Mohammad-Sohrabi/txxtea128-suite.git variant-E
cd variant-E
make
make test
make test-sanitize
```

This checkout includes only variant E's runtime sources and its local
helpers. No sibling project or original-library checkout is needed. Building
requires Make and a C11 compiler; tests also need Python 3. ASan/UBSan requires
a supporting compiler. OpenSSL libcrypto is required.


Same Encrypt-then-MAC construction as variant D, refactored for
**caller-managed message buffers**:

- `txxtea_etm_ctx` holds the two derived keys; `ctx_init` runs the HMAC
  KDF **once**, and you reuse the context for many messages
- **caller supplies the nonce** (you control uniqueness — required for CTR)
- `seal_into` / `open_into` write into **caller-provided buffers** — no
  direct buffer allocation in this wrapper (OpenSSL may allocate internally)
- tag verified with a constant-time compare before decryption

Output format: `"TX1" + version + nonce12 + ct_len_le32 + ciphertext + tag`.

> ⚠️ **Security status:** sound ETM + HMAC practice, but the cipher is
> the experimental variant B. Caller-supplied nonce means **you** are
> responsible for never reusing a `(ctx, nonce)` pair — reuse breaks CTR
> confidentiality.

## Files

| File              | Purpose                                       |
|-------------------|-----------------------------------------------|
| `txxtea_etm_ctx.h`| Public API (ctx init + seal_into/open_into)   |
| `txxtea_etm_ctx.c`| Implementation (needs libcrypto)              |
| `txxtea128.c/h`   | Embedded cipher (copy of variant B)           |
| `bench_etm_ctx.c` | Benchmark (seal/open ns per size)             |
| `Makefile`        | Build (Linux / macOS / Windows-MinGW)         |

## Requirements

OpenSSL **libcrypto** development headers and library are required.
The Makefile uses `pkg-config` or common Homebrew paths; CMake uses
`find_package(OpenSSL)`. Set `OPENSSL_ROOT_DIR` for a custom CMake prefix.

## Build

```sh
make          # builds bench_etm_ctx
make run
make clean
```

Windows (cmd.exe, MinGW gcc):

```
gcc -O2 -Wall -Wextra -Ic:\path\to\openssl\include -o bench_etm_ctx.exe txxtea128.c txxtea_etm_ctx.c bench_etm_ctx.c -Lc:\path\to\openssl\lib\MinGW -lcrypto
```

## API

```c
#include "txxtea_etm_ctx.h"

// Derive enc_key/mac_key from the 32-byte master key. Returns 1 on success.
int txxtea_etm_ctx_init(txxtea_etm_ctx *ctx, const uint8_t master_key[32]);

// Seal into caller buffer. out_cap must be >= TXXTEA_HEADER_LEN + pt_len + TXXTEA_TAG_LEN.
// nonce is 12 bytes, chosen by the caller (never reuse a (ctx, nonce) pair!).
int txxtea_etm_seal_into(const txxtea_etm_ctx *ctx,
                         const uint8_t *pt, size_t pt_len,
                         const uint8_t nonce12[TXXTEA_NONCE_LEN],
                         uint8_t *out, size_t out_cap, size_t *out_len);

// Verify tag, then decrypt into caller buffer. pt_cap must be >= ct_len.
int txxtea_etm_open_into(const txxtea_etm_ctx *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *pt, size_t pt_cap, size_t *pt_len);
```

## How it differs from the other variants

- **vs D:** same crypto, but D is one-shot with internal nonce and heap
  allocations; E gives you nonce control and a reusable caller-buffer API.
- **vs F:** F is E plus **Associated Data** (AAD) binding; if you need to
  authenticate headers/metadata, use F.
- **vs A/B/C/G:** cipher-only variants with no authentication layer.

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

Packets have a 32-bit plaintext-length field. Outputs and lengths must follow
the public header contract; on errors supplied lengths are reset to zero.
Authentication is checked before releasing plaintext. D/E/F use the same B
core and derived encryption keys: never reuse a master-key/nonce pair across
these formats. TX1 carries a 20-byte header and a 32-byte tag; TX2 carries a
24-byte header, clear authenticated AAD and a 32-byte tag.

Input/output/context/nonce/length storage must be disjoint. The caller manages
message buffers; OpenSSL may allocate internally. Clear the context after use
with the `*_ctx_clear` function declared in the public header.

See [CHANGELOG.md](CHANGELOG.md) for changes and migration notes.

## Explore the family

[Original XXTEA (main)](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/main) · [A](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/A) · [B](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/B) · [C](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/C) · [D](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/D) · [E](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/E) · [F](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/F) · [G](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/G)

Each A–G tag is a standalone source tree. The letters identify research
variants, not security levels. [archive/suite](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/archive/suite)
keeps the reviewed aggregate project and interoperability tests. The old
`v0.1.0`–`v0.9.0` tags remain unchanged historical milestones.

## License

See [LICENSE.md](LICENSE.md); original source attributions are retained.
