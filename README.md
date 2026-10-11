# Variant F · Encrypt-then-MAC · associated data

**Standalone tag `F`** · C implementation · Research project

```sh
git clone --branch F --single-branch https://github.com/C-Mohammad-Sohrabi/txxtea128-suite.git variant-F
cd variant-F
make
make test
make test-sanitize
```

This checkout includes only variant F's runtime sources and its local
helpers. No sibling project or original-library checkout is needed. Building
requires Make and a C11 compiler; tests also need Python 3. ASan/UBSan requires
a supporting compiler. OpenSSL libcrypto is required.


The most complete variant: Encrypt-then-MAC with **associated-data
binding**, on top of variant E's context-based, caller-buffer API (OpenSSL may allocate internally).

- magic `"TX2"` (a distinct envelope identifier; the version byte is still 1), header includes `aad_len`
- tag = `HMAC-SHA256(mac_key, header || aad || ciphertext)` — the
  associated data is **cryptographically bound** to the ciphertext, so
  headers, sender IDs, protocol metadata etc. cannot be swapped or altered
- output layout: `header || aad || ciphertext || tag`
- caller-supplied nonce + caller buffers (no malloc); constant-time tag
  verification before decryption

> ⚠️ **Security status:** sound ETM + HMAC + AAD practice, but the cipher
> is the experimental variant B. Nonce reuse is on the caller.

## Files

| File               | Purpose                                       |
|--------------------|-----------------------------------------------|
| `txxtea_etm_aad.h` | Public API (ctx init + seal_into/open_into)   |
| `txxtea_etm_aad.c` | Implementation (needs libcrypto)              |
| `txxtea128.c/h`    | Embedded cipher (copy of variant B)           |
| `demo_aad.c`       | Demo incl. AAD-tamper detection test          |
| `Makefile`         | Build (Linux / macOS / Windows-MinGW)         |

## Requirements

OpenSSL **libcrypto** development headers and library are required.
The Makefile uses `pkg-config` or common Homebrew paths; CMake uses
`find_package(OpenSSL)`. Set `OPENSSL_ROOT_DIR` for a custom CMake prefix.

## Build

```sh
make          # builds demo_aad
make run
make clean
```

Windows (cmd.exe, MinGW gcc):

```
gcc -O2 -Wall -Wextra -Ic:\path\to\openssl\include -o demo_aad.exe txxtea128.c txxtea_etm_aad.c demo_aad.c -Lc:\path\to\openssl\lib\MinGW -lcrypto
```

## API

```c
#include "txxtea_etm_aad.h"

int txxtea_etm_aad_ctx_init(txxtea_etm_aad_ctx *ctx, const uint8_t master_key[32]);

// Seal; out_cap must be >= TXXTEA_AAD_HEADER_LEN + aad_len + pt_len + TXXTEA_AAD_TAG_LEN.
int txxtea_etm_aad_seal_into(const txxtea_etm_aad_ctx *ctx,
                             const uint8_t *pt, size_t pt_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t nonce12[TXXTEA_AAD_NONCE_LEN],
                             uint8_t *out, size_t out_cap, size_t *out_len);

// Verify tag (over header || aad || ct), then decrypt.
int txxtea_etm_aad_open_into(const txxtea_etm_aad_ctx *ctx,
                             const uint8_t *in, size_t in_len,
                             uint8_t *pt, size_t pt_cap, size_t *pt_len,
                             uint8_t *aad_out, size_t aad_cap, size_t *aad_len);
```

## How it differs from the other variants

- **vs D:** D is one-shot, internal nonce, no AAD.
- **vs E:** identical API shape; E lacks AAD binding.
- **vs A/B/C/G:** cipher-only variants with no authentication layer.
- **Research scope:** F binds AAD and provides a caller-buffer API. It does
  not establish that the underlying B cipher is secure, nor does it include G.


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
