# Variant D · Encrypt-then-MAC · allocating API

**Standalone tag `D`** · C implementation · Research project

```sh
git clone --branch D --single-branch https://github.com/C-Mohammad-Sohrabi/txxtea128-suite.git variant-D
cd variant-D
make
make test
make test-sanitize
```

This checkout includes only variant D's runtime sources and its local
helpers. No sibling project or original-library checkout is needed. Building
requires Make and a C11 compiler; tests also need Python 3. ASan/UBSan requires
a supporting compiler. OpenSSL libcrypto is required.


A complete **symmetric authenticated-encryption** API: encrypts with the tweakable XXTEA-128
cipher in CTR mode and authenticates the result with **HMAC-SHA256**.

**Construction (Encrypt-then-MAC):**

- 32-byte master key → key separation via HMAC KDF:
  `enc_key = HMAC(master, "enc")[0..15]`, `mac_key = HMAC(master, "mac")`
- nonce: **12 random bytes from the OS CSPRNG** (`getrandom` on Linux,
  OpenSSL `RAND_bytes` on macOS/Windows)
- output format: `"TX1" + version + nonce12 + ct_len_le32 + ciphertext + tag`
- tag = `HMAC-SHA256(mac_key, header || ciphertext)`, verified with a
  **constant-time compare** before any decryption happens

> ⚠️ **Security status:** the ETM + HMAC construction is sound practice
> (tamper detection before decryption, key separation, constant-time tag
> check), but the underlying cipher is the experimental variant B — not a
> vetted cipher. No production-security claim is made for this construction.

## Files

| File             | Purpose                                        |
|------------------|------------------------------------------------|
| `txxtea_etm.h`   | Public API (`seal` / `open`)                   |
| `txxtea_etm.c`   | ETM implementation (needs libcrypto)           |
| `txxtea128.c/h`  | Embedded cipher (copy of variant B)            |
| `bench_etm.c`    | Benchmark (seal/open ns per size)              |
| `demo_etm.c`     | Demo incl. tamper-detection test               |
| `Makefile`       | Build (Linux / macOS / Windows-MinGW)          |

## Requirements

OpenSSL **libcrypto** (for HMAC, constant-time compare, RNG):

- Debian/Ubuntu: `sudo apt install libssl-dev`
- Fedora: `sudo dnf install openssl-devel`
- macOS: `brew install openssl`
- Windows: install OpenSSL for MinGW (or use MSYS2 `pacman -S mingw-w64-x86_64-openssl`)

## Build

```sh
make          # builds bench_etm + demo_etm
make run      # runs both
make clean
```

The Makefile auto-detects OpenSSL via `pkg-config` and falls back to
common Homebrew paths on macOS. Windows (cmd.exe, MinGW gcc on PATH):

```
gcc -O2 -Wall -Wextra -Ic:\path\to\openssl\include -o bench_etm.exe txxtea128.c txxtea_etm.c bench_etm.c -Lc:\path\to\openssl\lib\MinGW -lcrypto
```

## API

```c
#include "txxtea_etm.h"

// Seal (encrypt + authenticate). Allocates *out — caller frees it.
// Returns 1 on success, 0 on failure.
int txxtea_etm_seal(const uint8_t *pt, size_t pt_len,
                    const uint8_t master_key[32],
                    uint8_t **out, size_t *out_len);

// Open (verify tag, then decrypt). Allocates *pt — caller frees it.
// Returns 1 only if the tag is valid; tampered input is rejected.
int txxtea_etm_open(const uint8_t *in, size_t in_len,
                    const uint8_t master_key[32],
                    uint8_t **pt, size_t *pt_len);
```

**Usage notes:** nonce is generated internally — safe defaults, but you
relinquish control over nonce management. If you need caller-supplied
nonces or zero-allocation operation, use variant E; for associated-data
binding, use variant F.

## How it differs from the other variants

- **vs A/B/C:** raw ciphers with no authentication — tampering is undetectable.
- **vs E:** same cryptography, but E is context-based (precomputed keys,
  caller nonce + buffers, no malloc).
- **vs F:** F adds Associated Data (AAD) and uses the same ctx-based API.
- **vs G:** G is a cipher-only redesign (redesigned, unvetted core, no authentication
  layer); using G requires adapting the called function/header and assigning a new envelope identifier; it changes ciphertext compatibility.

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

See [CHANGELOG.md](CHANGELOG.md) for changes and migration notes.

## Explore the family

[Original XXTEA (main)](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/main) · [A](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/A) · [B](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/B) · [C](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/C) · [D](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/D) · [E](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/E) · [F](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/F) · [G](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/G)

Each A–G tag is a standalone source tree. The letters identify research
variants, not security levels. [archive/suite](https://github.com/C-Mohammad-Sohrabi/txxtea128-suite/tree/archive/suite)
keeps the reviewed aggregate project and interoperability tests. The old
`v0.1.0`–`v0.9.0` tags remain unchanged historical milestones.

## License

See [LICENSE.md](LICENSE.md); original source attributions are retained.
