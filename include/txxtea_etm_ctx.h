// txxtea_etm_ctx.h
#ifndef TXXTEA_ETM_CTX_H
#define TXXTEA_ETM_CTX_H

#include <stddef.h>
#include <stdint.h>

#define TXXTEA_MAGIC0 'T'
#define TXXTEA_MAGIC1 'X'
#define TXXTEA_MAGIC2 '1'
#define TXXTEA_VERSION 1

#define TXXTEA_NONCE_LEN 12
#define TXXTEA_TAG_LEN   32

// header = "TX1" + ver + nonce12 + ct_len_le32  => 20 bytes
#define TXXTEA_HEADER_LEN (3 + 1 + TXXTEA_NONCE_LEN + 4)

typedef struct {
    uint8_t enc_key[16];
    uint8_t mac_key[32];
} txxtea_etm_ctx;

// Init ctx from 32-byte master key.
// Returns 1 on success.
int txxtea_etm_ctx_init(txxtea_etm_ctx *ctx, const uint8_t master_key[32]);

// Output format (binary):
//  header (20 bytes) || ciphertext (pt_len bytes) || tag (32 bytes)
//
// seal_into requires caller-supplied nonce (12 bytes).
// Returns 1 on success.
int txxtea_etm_seal_into(const txxtea_etm_ctx *ctx,
                         const uint8_t *pt, size_t pt_len,
                         const uint8_t nonce12[TXXTEA_NONCE_LEN],
                         uint8_t *out, size_t out_cap,
                         size_t *out_len);

// open_into verifies tag before decrypting.
// pt_cap must be >= ciphertext_len.
// Returns 1 on success (and sets pt_len).
int txxtea_etm_open_into(const txxtea_etm_ctx *ctx,
                         const uint8_t *in, size_t in_len,
                         uint8_t *pt, size_t pt_cap,
                         size_t *pt_len);

// On failure, supplied output lengths are zero; allocating APIs also return NULL.
// Input, output, context, nonce and length-variable storage must not overlap.
// E/F caller nonces must be unique for a given master key across both formats.
// Erase the reusable secret keys when the context is no longer needed.
void txxtea_etm_ctx_clear(txxtea_etm_ctx *ctx);

#endif
