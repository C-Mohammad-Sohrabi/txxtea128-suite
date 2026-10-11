# txxtea128-suite

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

## Introduction
xxtea128-suite is an experimental C research suite exploring XXTEA-derived
fixed-block, tweakable, and authenticated-encryption constructions.

It is intended for academic evaluation, benchmarking, and design exploration,
not for production cryptography.

> Warning: This project is experimental and has not been reviewed by
> independent cryptanalysts. Do not use it to protect real-world data.

## Acknowledgements

This project was inspired by the upstream `xxtea-c` project and related
XXTEA implementations. The constructions and experimental variants in this
repository are independent research work and should not be interpreted as
part of the upstream project.

## Security Notes

- Experimental construction
- Not reviewed by external cryptanalysts
- Do not use for production security
- Prefer standardized AEAD schemes such as AES-GCM or ChaCha20-Poly1305
  for real-world applications

# Build
## Installation

```sh
git clone https://github.com/C-Mohammad-Sohrabi/txxtea128-suite.git
cmake .
make
make install
```

## Usage

```c
#include <stdio.h>
#include <string.h>
#include <xxtea.h>

int main() {
    const char *text = "Hello World! 你好，中国！";
    const char *key = "1234567890";
    size_t len;
    unsigned char *encrypt_data = xxtea_encrypt(text, strlen(text), key, &len);
    char *decrypt_data = xxtea_decrypt(encrypt_data, len, key, &len);
    if (strncmp(text, decrypt_data, len) == 0) {
        printf("success!\n");
    }
    else {
        printf("fail!\n");
    }
    free(encrypt_data);
    free(decrypt_data);
    return 0;
}
```

## Variants (experimental playground)

The `variants/variant_A` … `variants/variant_G` folders reshape XXTEA
into a fixed 128-bit block cipher, run it in CTR mode, and (D/E/F) wrap
it in authenticated encryption. Each folder has its own README, Makefile and benchmark; the cipher sources
also use the shared root `crypto_util.h`. Standalone tags bundle that helper. Build everything (or one)
with:

```sh
make all            # build root bench + every variant + the test menu
make variant_G      # build one variant
make VARIANT=F      # same, by name
make menu           # build the interactive test menu
./menu              # pick a component and run its self-test
make run            # build + run every benchmark/demo
```

Windows users: run `build_windows.bat` (needs MinGW-w64 gcc; variants
D/E/F also need OpenSSL).

**Releases (tags)** — the suite grows one milestone at a time; each tag
is a self-contained snapshot you can check out and build on its own:

| Tag | Contents |
|---|---|
| `v0.1.0` | Original XXTEA library + benchmark |
| `v0.2.0` | + variant A (XXTEA-128 block cipher, CTR) |
| `v0.3.0` | + variant B (tweakable) |
| `v0.4.0` | + variant C (round-key schedule) |
| `v0.5.0` | + variant D (Encrypt-then-MAC) |
| `v0.6.0` | + variant E (ETM, context API) |
| `v0.7.0` | + variant F (ETM + AAD) |
| `v0.8.0` | + variant G (hardened cipher) |
| `v0.9.0` | Aggregate build + Windows script + test menu |

The letters describe different structures, not an established security
ranking. B injects its tweak inside each MX update; C retains that path and
adds a schedule; D/E/F use B, while G is a separate core.

## Verified implementation and API contracts (2026-10-10)

Run `make test` for the independent Python reference, frozen known-answer
vectors, all seven variants, D/E interoperability and authenticated envelope
negative tests. Run `make test-sanitize` to also run the C memory/UB checks.
The tests require Python 3, a C compiler, and real OpenSSL libcrypto.
`make -B all` rebuilds all demos; CMake builds the base library and example.

The original `xxtea_encrypt` / `xxtea_decrypt` retain historical **string-key**
semantics (stop at the first NUL, zero-pad to 16 bytes). Use the new
`xxtea_encrypt_raw` / `xxtea_decrypt_raw` for exactly 16 binary key bytes.
Old ciphertext produced by truncated binary keys must still be opened with
the legacy API; changing to raw keys changes that ciphertext. No auto-detection
is safe. All base API errors return NULL and set a supplied output length to 0.
Empty messages are unsupported by the base envelope, but supported by D/E/F.

All variant `*_ctr_xor` functions now return 1/0; callers must check the result.
They reject more than 2^32 counter blocks (2^36 bytes) before touching data.
Each call restarts the counter: this is a one-shot API, not a streaming update.
A key/nonce pair must not be reused, including across D/E/F formats, because
these wrappers derive the same encryption key. The limit is a counter-space
bound, not a certified safe per-key data volume. Existing callers that ignore
the return value compile, but must be updated to handle failures.

D/E/F keep their wire formats. Output lengths are reset on failure. E/F
require disjoint input/output/context/nonce/length storage; block APIs support
exact in-place operation. `txxtea_etm_ctx_clear` and
`txxtea_etm_aad_ctx_clear` erase reusable key material. E/F do not allocate
message buffers themselves; OpenSSL can allocate internally. For integration,
link just one copy of the identical B/D/E/F `txxtea128.c` core, not four.
G is a separate research branch, not the core currently used in D/E/F.

Passing these correctness tests is not a cryptanalytic security proof or
constant-time audit. Native 32-bit, Windows, big-endian and embedded targets
have not been executed in this review. Personal Word documents are excluded
from version control.

F constants now use the `TXXTEA_AAD_` prefix (for example
`TXXTEA_AAD_HEADER_LEN`), so E and F headers can coexist without conflicting
20/24-byte header macros. Update old F callers that used the generic macros.
