# variant_D — Authenticated encryption (Encrypt-then-MAC)

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
> vetted cipher. For production, swap the core for AES-CTR or ChaCha20.

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