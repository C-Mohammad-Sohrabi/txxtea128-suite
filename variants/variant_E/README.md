# variant_E — Authenticated encryption with a reusable context

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

OpenSSL **libcrypto** — same installs as variant D (see `../variant_D/README.md`).

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