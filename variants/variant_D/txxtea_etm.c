// txxtea_etm.c
#include "txxtea_etm.h"
#include "txxtea128.h"   

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#ifdef __linux__
#include <sys/random.h>
#endif

#define MAGIC0 'T'
#define MAGIC1 'X'
#define MAGIC2 '1'
#define VERSION 1

#define NONCE_LEN 12
#define TAG_LEN 32

static void store_le32(uint8_t out[4], uint32_t x) {
    out[0] = (uint8_t)x;
    out[1] = (uint8_t)(x >> 8);
    out[2] = (uint8_t)(x >> 16);
    out[3] = (uint8_t)(x >> 24);
}

static uint32_t load_le32(const uint8_t in[4]) {
    return (uint32_t)in[0]
        | ((uint32_t)in[1] << 8)
        | ((uint32_t)in[2] << 16)
        | ((uint32_t)in[3] << 24);
}

static int random_bytes(uint8_t *buf, size_t n) {
#ifdef __linux__
    // getrandom preferred on modern Debian
    size_t off = 0;
    while (off < n) {
        ssize_t r = getrandom(buf + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (r == 0) return 0;
        off += (size_t)r;
    }
    return 1;
#else
    // macOS / Windows: use the OpenSSL CSPRNG (libcrypto is already
    // linked for HMAC); n here is the 12-byte nonce, so no int overflow.
    return RAND_bytes(buf, (int)n) == 1;
#endif
}

// Simple key separation using HMAC(master, label).
// enc_key = first 16 bytes of HMAC(master, "enc")
// mac_key = full 32 bytes of HMAC(master, "mac")
static int derive_keys(const uint8_t master_key[32],
                       uint8_t enc_key16[16],
                       uint8_t mac_key32[32]) {
    unsigned int outlen = 0;
    uint8_t tmp[TAG_LEN];

    // enc
    if (!HMAC(EVP_sha256(), master_key, 32,
              (const unsigned char*)"enc", 3, tmp, &outlen)) goto key_fail;
    if (outlen != 32) goto key_fail;
    memcpy(enc_key16, tmp, 16);

    // mac
    if (!HMAC(EVP_sha256(), master_key, 32,
              (const unsigned char*)"mac", 3, mac_key32, &outlen)) goto key_fail;
    if (outlen != 32) goto key_fail;

    OPENSSL_cleanse(tmp, sizeof(tmp));
    return 1;
key_fail:
    OPENSSL_cleanse(tmp, sizeof(tmp));
    OPENSSL_cleanse(enc_key16, 16);
    OPENSSL_cleanse(mac_key32, 32);
    return 0;
}

static int compute_tag(uint8_t tag_out[32],
                       const uint8_t mac_key32[32],
                       const uint8_t *data, size_t data_len) {
    unsigned int outlen = 0;
    if (!HMAC(EVP_sha256(), mac_key32, 32, data, data_len, tag_out, &outlen))
        return 0;
    return outlen == 32;
}

int txxtea_etm_seal(const uint8_t *pt, size_t pt_len,
                    const uint8_t master_key[32],
                    uint8_t **out, size_t *out_len) {
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if ((!pt && pt_len) || !out || !out_len || !master_key) return 0;
    if (pt_len > UINT32_MAX || pt_len > SIZE_MAX - 52) return 0;

    uint8_t enc_key[16];
    uint8_t mac_key[32];
    if (!derive_keys(master_key, enc_key, mac_key)) return 0;

    uint8_t nonce[NONCE_LEN];
    if (!random_bytes(nonce, sizeof(nonce))) {
        OPENSSL_cleanse(enc_key, sizeof(enc_key));
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
        return 0;
    }

    // Allocate output buffer
    // header = 3 magic + 1 ver + 12 nonce + 4 len = 20 bytes
    const size_t header_len = 3 + 1 + NONCE_LEN + 4;
    const size_t ct_len = pt_len;
    const size_t total = header_len + ct_len + TAG_LEN;

    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) {
        OPENSSL_cleanse(enc_key, sizeof(enc_key));
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
        return 0;
    }

    // Header
    buf[0] = MAGIC0;
    buf[1] = MAGIC1;
    buf[2] = MAGIC2;
    buf[3] = VERSION;
    memcpy(buf + 4, nonce, NONCE_LEN);
    store_le32(buf + 4 + NONCE_LEN, (uint32_t)ct_len);

    // Ciphertext = pt XOR keystream (CTR)
    uint8_t *ct = buf + header_len;
    if (ct_len) memcpy(ct, pt, ct_len);
    txxtea128_ctr_xor(ct, ct_len, enc_key, nonce);

    // Tag over (header || ciphertext)
    uint8_t *tag = buf + header_len + ct_len;
    if (!compute_tag(tag, mac_key, buf, header_len + ct_len)) {
        OPENSSL_cleanse(enc_key, sizeof(enc_key));
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
        OPENSSL_cleanse(buf, total);
        free(buf);
        return 0;
    }

    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));

    *out = buf;
    *out_len = total;
    return 1;
}

int txxtea_etm_open(const uint8_t *in, size_t in_len,
                    const uint8_t master_key[32],
                    uint8_t **pt, size_t *pt_len) {
    if (pt) *pt = NULL;
    if (pt_len) *pt_len = 0;
    if (!in || !pt || !pt_len || !master_key) return 0;

    const size_t header_len = 3 + 1 + NONCE_LEN + 4;
    if (in_len < header_len + TAG_LEN) return 0;

    // Check magic/version
    if (in[0] != MAGIC0 || in[1] != MAGIC1 || in[2] != MAGIC2) return 0;
    if (in[3] != VERSION) return 0;

    const uint8_t *nonce = in + 4;
    uint32_t ct_len_u32 = load_le32(in + 4 + NONCE_LEN);

    size_t ct_len = (size_t)ct_len_u32;
    if (ct_len != in_len - header_len - TAG_LEN) return 0;

    const uint8_t *ct = in + header_len;
    const uint8_t *tag = in + header_len + ct_len;

    uint8_t enc_key[16];
    uint8_t mac_key[32];
    if (!derive_keys(master_key, enc_key, mac_key)) return 0;

    // Verify tag (constant-time compare)
    uint8_t tag_calc[32];
    if (!compute_tag(tag_calc, mac_key, in, header_len + ct_len)) {
        OPENSSL_cleanse(tag_calc, sizeof(tag_calc));
        OPENSSL_cleanse(enc_key, sizeof(enc_key));
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
        return 0;
    }

    if (CRYPTO_memcmp(tag, tag_calc, 32) != 0) {
        OPENSSL_cleanse(enc_key, sizeof(enc_key));
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
        OPENSSL_cleanse(tag_calc, sizeof(tag_calc));
        return 0;
    }

    // Decrypt
    uint8_t *out_pt = (uint8_t*)malloc(ct_len ? ct_len : 1);
    if (!out_pt) {
        OPENSSL_cleanse(enc_key, sizeof(enc_key));
        OPENSSL_cleanse(mac_key, sizeof(mac_key));
        OPENSSL_cleanse(tag_calc, sizeof(tag_calc));
        return 0;
    }
    if (ct_len) memcpy(out_pt, ct, ct_len);
    txxtea128_ctr_xor(out_pt, ct_len, enc_key, nonce);

    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    OPENSSL_cleanse(tag_calc, sizeof(tag_calc));

    *pt = out_pt;
    *pt_len = ct_len;
    return 1;
}
