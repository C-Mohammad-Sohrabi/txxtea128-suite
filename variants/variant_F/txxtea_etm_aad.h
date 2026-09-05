// txxtea_etm_aad.h
#ifndef TXXTEA_ETM_AAD_H
#define TXXTEA_ETM_AAD_H

#include <stddef.h>
#include <stdint.h>

#define TXXTEA_MAGIC0 'T'
#define TXXTEA_MAGIC1 'X'
#define TXXTEA_MAGIC2 '2'   // نسخه جدید با AAD
#define TXXTEA_VERSION 1

#define TXXTEA_NONCE_LEN 12
#define TXXTEA_TAG_LEN   32

// header = "TX2" + ver + nonce12 + ct_len_le32 + aad_len_le32
#define TXXTEA_HEADER_LEN (3 + 1 + TXXTEA_NONCE_LEN + 4 + 4)

typedef struct {
    uint8_t enc_key[16];
    uint8_t mac_key[32];
} txxtea_etm_aad_ctx;

// Init ctx from 32-byte master key.
int txxtea_etm_aad_ctx_init(txxtea_etm_aad_ctx *ctx, const uint8_t master_key[32]);

// Output format:
// header || aad || ciphertext || tag
//
// tag = HMAC(mac_key, header || aad || ciphertext)
// ciphertext = CTR(enc_key, nonce, pt)
int txxtea_etm_aad_seal_into(const txxtea_etm_aad_ctx *ctx,
                             const uint8_t *pt, size_t pt_len,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t nonce12[TXXTEA_NONCE_LEN],
                             uint8_t *out, size_t out_cap,
                             size_t *out_len);

int txxtea_etm_aad_open_into(const txxtea_etm_aad_ctx *ctx,
                             const uint8_t *in, size_t in_len,
                             uint8_t *pt, size_t pt_cap,
                             size_t *pt_len,
                             uint8_t *aad_out, size_t aad_cap,
                             size_t *aad_len);

#endif
