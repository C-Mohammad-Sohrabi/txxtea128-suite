# XXTEA for C

<a href="https://github.com/xxtea/">
    <img src="https://avatars1.githubusercontent.com/u/6683159?v=3&s=86" alt="XXTEA logo" title="XXTEA" align="right" />
</a>

## Introduction

XXTEA is a fast and secure encryption algorithm. This is a XXTEA library for C.

It is different from the original XXTEA encryption algorithm. It encrypts and decrypts raw binary data instead of 32bit integer array, and the key is also the raw binary data.

## Installation

```sh
git clone https://github.com/xxtea/xxtea-c.git
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
it in authenticated encryption. Each folder is a self-contained project
with its own README, Makefile and benchmark. Build everything (or one)
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

**Which variant should I use?**

| Variant | What it is | Use it if… |
|---|---|---|
| A | XXTEA-128 fixed block cipher, CTR mode | you want the minimal baseline |
| B | A + 16-byte tweak (weak final-XOR injection) | you need a tweak and accept its limits |
| C | B + linear per-round key schedule | you want the strongest *original* design among A–C |
| D | Encrypt-then-MAC, HMAC-SHA256, one-shot API | you want authenticated encryption fast |
| E | Same as D, ctx-based, no malloc, caller nonce | you need a reusable zero-allocation API |
| F | Same as E + Associated Data (AAD) binding | you want the most complete package (recommended) |
| G | Hardened cipher: 32 rounds, whitening, feedback schedule | you want the strongest raw XXTEA-family core |

> ⚠️ All variants are **experimental, unvetted ciphers** (XXTEA has
> published cryptanalysis). For production, prefer a vetted primitive
> (AES-CTR, ChaCha20-Poly1305) wrapped in the variant F construction.

