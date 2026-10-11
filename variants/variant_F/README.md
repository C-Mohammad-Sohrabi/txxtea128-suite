# variant_F — Authenticated encryption with Associated Data (AAD)

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

OpenSSL **libcrypto** — same installs as variant D (see `../variant_D/README.md`).

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
