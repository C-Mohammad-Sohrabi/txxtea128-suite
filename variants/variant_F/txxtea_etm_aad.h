// txxtea_etm_aad.h
#ifndef TXXTEA_ETM_AAD_H
#define TXXTEA_ETM_AAD_H

#include <stddef.h>
#include <stdint.h>

#define TXXTEA_AAD_MAGIC0 'T'
#define TXXTEA_AAD_MAGIC1 'X'
#define TXXTEA_AAD_MAGIC2 '2'   // نسخه جدید با AAD
#define TXXTEA_AAD_VERSION 1

#define TXXTEA_AAD_NONCE_LEN 12
#define TXXTEA_AAD_TAG_LEN   32

// header = "TX2" + ver + nonce12 + ct_len_le32 + aad_len_le32
#define TXXTEA_AAD_HEADER_LEN (3 + 1 + TXXTEA_AAD_NONCE_LEN + 4 + 4)

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
                             const uint8_t nonce12[TXXTEA_AAD_NONCE_LEN],
                             uint8_t *out, size_t out_cap,
                             size_t *out_len);

int txxtea_etm_aad_open_into(const txxtea_etm_aad_ctx *ctx,
                             const uint8_t *in, size_t in_len,
                             uint8_t *pt, size_t pt_cap,
                             size_t *pt_len,
                             uint8_t *aad_out, size_t aad_cap,
                             size_t *aad_len);

// On failure, supplied output lengths are zero; allocating APIs also return NULL.
// Input, output, context, nonce and length-variable storage must not overlap.
// E/F caller nonces must be unique for a given master key across both formats.
// Erase the reusable secret keys when the context is no longer needed.
void txxtea_etm_aad_ctx_clear(txxtea_etm_aad_ctx *ctx);

#endif
