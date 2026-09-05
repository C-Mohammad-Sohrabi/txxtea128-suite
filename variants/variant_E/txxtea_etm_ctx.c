// txxtea_etm_ctx.c
#include "txxtea_etm_ctx.h"
#include "txxtea128.h"   // Variant B: txxtea128_ctr_xor

#include <string.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

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

// key separation: enc_key = HMAC(master, "enc")[0..15], mac_key = HMAC(master,"mac")[0..31]
int txxtea_etm_ctx_init(txxtea_etm_ctx *ctx, const uint8_t master_key[32]) {
    if (!ctx || !master_key) return 0;

    unsigned int outlen = 0;
    uint8_t tmp[32];

    if (!HMAC(EVP_sha256(), master_key, 32,
              (const unsigned char*)"enc", 3, tmp, &outlen)) return 0;
    if (outlen != 32) return 0;
    memcpy(ctx->enc_key, tmp, 16);

    if (!HMAC(EVP_sha256(), master_key, 32,
              (const unsigned char*)"mac", 3, ctx->mac_key, &outlen)) return 0;
    if (outlen != 32) return 0;

    OPENSSL_cleanse(tmp, sizeof(tmp));
    return 1;
}

static int hmac_sha256(uint8_t out[32], const uint8_t key[32],
                       const uint8_t *data, size_t data_len) {
    unsigned int outlen = 0;
    if (!HMAC(EVP_sha256(), key, 32, data, data_len, out, &outlen)) return 0;
    return outlen == 32;
}

int txxtea_etm_seal_into(const txxtea_etm_ctx *ctx,
                         const uint8_t *pt, size_t pt_len,
                         const uint8_t nonce12[TXXTEA_NONCE_LEN],
                         uint8_t *out, size_t out_cap,
                         size_t *out_len) {
    if (!ctx || (!pt && pt_len) || !nonce12 || !out || !out_len) return 0;
    if (pt_len > 0xFFFFFFFFu) return 0;

    const size_t total = TXXTEA_HEADER_LEN + pt_len + TXXTEA_TAG_LEN;
    if (out_cap < total) return 0;

    // header
    out[0] = TXXTEA_MAGIC0;
    out[1] = TXXTEA_MAGIC1;
    out[2] = TXXTEA_MAGIC2;
    out[3] = TXXTEA_VERSION;
    memcpy(out + 4, nonce12, TXXTEA_NONCE_LEN);
    store_le32(out + 4 + TXXTEA_NONCE_LEN, (uint32_t)pt_len);

    // ciphertext (in-place)
    uint8_t *ct = out + TXXTEA_HEADER_LEN;
    if (pt_len) memcpy(ct, pt, pt_len);
    txxtea128_ctr_xor(ct, pt_len, ctx->enc_key, nonce12);

    // tag over (header || ciphertext)
    uint8_t *tag = out + TXXTEA_HEADER_LEN + pt_len;
    if (!hmac_sha256(tag, ctx->mac_key, out, TXXTEA_HEADER_LEN + pt_len)) {
        OPENSSL_cleanse(out, total);
        return 0;
    }

    *out_len = total;
    return 1;
}

int txxtea_etm_open_into(const txxtea_etm_ctx *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *pt, size_t pt_cap,
                         size_t *pt_len) {
    if (!ctx || !in || !pt || !pt_len) return 0;
    if (in_len < TXXTEA_HEADER_LEN + TXXTEA_TAG_LEN) return 0;

    // magic/version
    if (in[0] != TXXTEA_MAGIC0 || in[1] != TXXTEA_MAGIC1 || in[2] != TXXTEA_MAGIC2) return 0;
    if (in[3] != TXXTEA_VERSION) return 0;

    const uint8_t *nonce = in + 4;
    uint32_t ct_len_u32 = load_le32(in + 4 + TXXTEA_NONCE_LEN);
    size_t ct_len = (size_t)ct_len_u32;

    size_t expected = TXXTEA_HEADER_LEN + ct_len + TXXTEA_TAG_LEN;
    if (expected != in_len) return 0;
    if (pt_cap < ct_len) return 0;

    const uint8_t *ct  = in + TXXTEA_HEADER_LEN;
    const uint8_t *tag = in + TXXTEA_HEADER_LEN + ct_len;

    // verify tag first
    uint8_t calc[32];
    if (!hmac_sha256(calc, ctx->mac_key, in, TXXTEA_HEADER_LEN + ct_len)) {
        OPENSSL_cleanse(calc, sizeof(calc));
        return 0;
    }
    if (CRYPTO_memcmp(tag, calc, 32) != 0) {
        OPENSSL_cleanse(calc, sizeof(calc));
        return 0;
    }
    OPENSSL_cleanse(calc, sizeof(calc));

    // decrypt
    if (ct_len) memcpy(pt, ct, ct_len);
    txxtea128_ctr_xor(pt, ct_len, ctx->enc_key, nonce);

    *pt_len = ct_len;
    return 1;
}
