// txxtea_etm_aad.c
#include "txxtea_etm_aad.h"
#include "txxtea128.h"

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

static int hmac_sha256(uint8_t out[32], const uint8_t key[32],
                       const uint8_t *data, size_t data_len) {
    unsigned int outlen = 0;
    if (!HMAC(EVP_sha256(), key, 32, data, data_len, out, &outlen)) return 0;
    return outlen == 32;
}

int txxtea_etm_aad_ctx_init(txxtea_etm_aad_ctx *ctx, const uint8_t master_key[32]) {
    if (!ctx || !master_key) return 0;

    unsigned int outlen = 0;
    uint8_t tmp[32];

    if (!HMAC(EVP_sha256(), master_key, 32,
              (const unsigned char*)"enc", 3, tmp, &outlen)) goto key_fail;
    if (outlen != 32) goto key_fail;
    memcpy(ctx->enc_key, tmp, 16);

    if (!HMAC(EVP_sha256(), master_key, 32,
              (const unsigned char*)"mac", 3, ctx->mac_key, &outlen)) goto key_fail;
    if (outlen != 32) goto key_fail;

    OPENSSL_cleanse(tmp, sizeof(tmp));
    return 1;
key_fail:
    OPENSSL_cleanse(tmp, sizeof(tmp));
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    return 0;
}

int txxtea_etm_aad_seal_into(const txxtea_etm_aad_ctx *ctx,
                             const uint8_t *pt, size_t pt_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t nonce12[TXXTEA_AAD_NONCE_LEN],
                             uint8_t *out, size_t out_cap,
                             size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!ctx || (!pt && pt_len) || (!aad && aad_len) || !nonce12 || !out || !out_len) return 0;
    if (pt_len > 0xFFFFFFFFu || aad_len > 0xFFFFFFFFu) return 0;

    if (aad_len > SIZE_MAX - TXXTEA_AAD_HEADER_LEN - TXXTEA_AAD_TAG_LEN) return 0;
    if (pt_len > SIZE_MAX - TXXTEA_AAD_HEADER_LEN - TXXTEA_AAD_TAG_LEN - aad_len) return 0;
    size_t total = TXXTEA_AAD_HEADER_LEN + aad_len + pt_len + TXXTEA_AAD_TAG_LEN;
    if (out_cap < total) return 0;

    // header
    out[0] = TXXTEA_AAD_MAGIC0;
    out[1] = TXXTEA_AAD_MAGIC1;
    out[2] = TXXTEA_AAD_MAGIC2;
    out[3] = TXXTEA_AAD_VERSION;

    memcpy(out + 4, nonce12, TXXTEA_AAD_NONCE_LEN);
    store_le32(out + 4 + TXXTEA_AAD_NONCE_LEN, (uint32_t)pt_len);
    store_le32(out + 4 + TXXTEA_AAD_NONCE_LEN + 4, (uint32_t)aad_len);

    // aad
    uint8_t *aad_dst = out + TXXTEA_AAD_HEADER_LEN;
    if (aad_len) memcpy(aad_dst, aad, aad_len);

    // ciphertext
    uint8_t *ct = out + TXXTEA_AAD_HEADER_LEN + aad_len;
    if (pt_len) memcpy(ct, pt, pt_len);
    txxtea128_ctr_xor(ct, pt_len, ctx->enc_key, nonce12);

    // tag over header||aad||ciphertext
    uint8_t *tag = out + TXXTEA_AAD_HEADER_LEN + aad_len + pt_len;
    if (!hmac_sha256(tag, ctx->mac_key, out, TXXTEA_AAD_HEADER_LEN + aad_len + pt_len)) {
        OPENSSL_cleanse(out, total);
        return 0;
    }

    *out_len = total;
    return 1;
}

int txxtea_etm_aad_open_into(const txxtea_etm_aad_ctx *ctx,
                             const uint8_t *in, size_t in_len,
                             uint8_t *pt, size_t pt_cap,
                             size_t *pt_len,
                             uint8_t *aad_out, size_t aad_cap,
                             size_t *aad_len) {
    if (pt_len) *pt_len = 0;
    if (aad_len) *aad_len = 0;
    if (!ctx || !in || !pt || !pt_len || !aad_out || !aad_len) return 0;
    if (in_len < TXXTEA_AAD_HEADER_LEN + TXXTEA_AAD_TAG_LEN) return 0;

    if (in[0] != TXXTEA_AAD_MAGIC0 || in[1] != TXXTEA_AAD_MAGIC1 || in[2] != TXXTEA_AAD_MAGIC2) return 0;
    if (in[3] != TXXTEA_AAD_VERSION) return 0;

    const uint8_t *nonce = in + 4;
    size_t ct_len = (size_t)load_le32(in + 4 + TXXTEA_AAD_NONCE_LEN);
    size_t aadl   = (size_t)load_le32(in + 4 + TXXTEA_AAD_NONCE_LEN + 4);

    size_t payload_len = in_len - TXXTEA_AAD_HEADER_LEN - TXXTEA_AAD_TAG_LEN;
    if (aadl > payload_len || ct_len != payload_len - aadl) return 0;
    if (pt_cap < ct_len) return 0;
    if (aad_cap < aadl) return 0;

    const uint8_t *aad_ptr = in + TXXTEA_AAD_HEADER_LEN;
    const uint8_t *ct      = in + TXXTEA_AAD_HEADER_LEN + aadl;
    const uint8_t *tag     = in + TXXTEA_AAD_HEADER_LEN + aadl + ct_len;

    // verify tag
    uint8_t calc[32];
    if (!hmac_sha256(calc, ctx->mac_key, in, TXXTEA_AAD_HEADER_LEN + aadl + ct_len)) {
        OPENSSL_cleanse(calc, sizeof(calc));
        return 0;
    }
    if (CRYPTO_memcmp(tag, calc, 32) != 0) {
        OPENSSL_cleanse(calc, sizeof(calc));
        return 0;
    }
    OPENSSL_cleanse(calc, sizeof(calc));

    // output aad
    if (aadl) memcpy(aad_out, aad_ptr, aadl);
    *aad_len = aadl;

    // decrypt
    if (ct_len) memcpy(pt, ct, ct_len);
    txxtea128_ctr_xor(pt, ct_len, ctx->enc_key, nonce);
    *pt_len = ct_len;

    return 1;
}

void txxtea_etm_aad_ctx_clear(txxtea_etm_aad_ctx *ctx) {
    if (ctx) OPENSSL_cleanse(ctx, sizeof(*ctx));
}
