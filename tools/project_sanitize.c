/* One-project ASan/UBSan driver; PROJECT_* selects only local public headers. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(PROJECT_ORIGINAL)
#include "xxtea.h"
#include "example/base64.h"
#elif defined(PROJECT_A)
#include "xxtea128.h"
#define STREAM xxtea128_ctr_xor
#elif defined(PROJECT_C)
#include "txxtea128_rs.h"
#define STREAM txxtea128_rs_ctr_xor
#elif defined(PROJECT_G)
#include "txxtea128_h.h"
#define STREAM txxtea128_h_ctr_xor
#else
#include "txxtea128.h"
#define STREAM txxtea128_ctr_xor
#endif
#if defined(PROJECT_D)
#include "txxtea_etm.h"
#elif defined(PROJECT_E)
#include "txxtea_etm_ctx.h"
#elif defined(PROJECT_F)
#include "txxtea_etm_aad.h"
#endif
static uint32_t state = 20261010;
static uint8_t next_byte(void) {
    state ^= state << 13; state ^= state >> 17; state ^= state << 5;
    return (uint8_t)state;
}
int main(void) {
    uint8_t key[32] = {0}, input[512];
#if defined(PROJECT_ORIGINAL)
    size_t n, m;
    char *short_key = malloc(2); assert(short_key); strcpy(short_key, "k");
    void *first = xxtea_encrypt("hello", 5, short_key, &n);
    assert(first); free(first); free(short_key);
#else
    uint8_t nonce[12] = {0}, stream[512];
#endif
#if defined(PROJECT_D) || defined(PROJECT_E) || defined(PROJECT_F)
    size_t n, m;
#endif
#if defined(PROJECT_E) || defined(PROJECT_F)
    uint8_t out[1100], pt[512];
#endif
#if defined(PROJECT_E)
    txxtea_etm_ctx ctx; assert(txxtea_etm_ctx_init(&ctx, key));
#elif defined(PROJECT_F)
    txxtea_etm_aad_ctx ctx; assert(txxtea_etm_aad_ctx_init(&ctx, key));
    uint8_t aad[512]; size_t an;
#endif
    for (size_t len = 0; len < sizeof(input); ++len) {
        for (size_t j = 0; j < len; ++j) input[j] = next_byte();
#if defined(PROJECT_ORIGINAL)
        if (len) {
            void *ct = xxtea_encrypt_raw(input, len, key, &n); assert(ct);
            void *pt = xxtea_decrypt_raw(ct, n, key, &m);
            assert(pt && m == len && !memcmp(pt, input, len)); free(ct); free(pt);
            char *encoded = base64_encode(input, len); assert(encoded);
            void *decoded = base64_decode(encoded, &m);
            assert(decoded && m == len && !memcmp(decoded, input, len)); free(decoded); free(encoded);
        }
#else
        memcpy(stream, input, len);
        assert(STREAM(stream, len, key, nonce));
        assert(STREAM(stream, len, key, nonce));
        assert(!memcmp(stream, input, len));
#endif
#if defined(PROJECT_D)
        uint8_t *ct = NULL, *pt = NULL;
        assert(txxtea_etm_seal(input, len, key, &ct, &n));
        assert(txxtea_etm_open(ct, n, key, &pt, &m));
        assert(m == len && !memcmp(pt, input, len)); free(ct); free(pt);
#elif defined(PROJECT_E)
        assert(txxtea_etm_seal_into(&ctx, input, len, nonce, out, sizeof(out), &n));
        assert(txxtea_etm_open_into(&ctx, out, n, pt, sizeof(pt), &m));
        assert(m == len && !memcmp(pt, input, len));
#elif defined(PROJECT_F)
        assert(txxtea_etm_aad_seal_into(&ctx, input, len, input, len % 31, nonce, out, sizeof(out), &n));
        assert(txxtea_etm_aad_open_into(&ctx, out, n, pt, sizeof(pt), &m, aad, sizeof(aad), &an));
        assert(m == len && an == len % 31 && !memcmp(pt, input, len) && !memcmp(aad, input, an));
#endif
    }
#if defined(PROJECT_ORIGINAL)
    const char *bad[] = {"!!!!", "====", "AA=A", "AA==AAAA", "AB==", "AAB=", "\xff\xff\xff\xff"};
    for (size_t j = 0; j < sizeof(bad)/sizeof(*bad); ++j) {
        n = 99; assert(!base64_decode(bad[j], &n) && !n);
    }
#endif
#if defined(PROJECT_ORIGINAL) || defined(PROJECT_D) || defined(PROJECT_E) || defined(PROJECT_F)
    for (size_t trial = 0; trial < 5000; ++trial) {
        size_t len = next_byte();
        for (size_t j = 0; j < len; ++j) input[j] = next_byte();
#if defined(PROJECT_ORIGINAL)
        free(xxtea_decrypt_raw(input, len, key, &n));
#elif defined(PROJECT_D)
        uint8_t *p = NULL; assert(!txxtea_etm_open(input, len, key, &p, &n));
#elif defined(PROJECT_E)
        assert(!txxtea_etm_open_into(&ctx, input, len, pt, sizeof(pt), &m));
#elif defined(PROJECT_F)
        assert(!txxtea_etm_aad_open_into(&ctx, input, len, pt, sizeof(pt), &m, aad, sizeof(aad), &an));
#endif
    }
#endif
#if defined(PROJECT_E)
    if (SIZE_MAX == UINT32_MAX)
        assert(!txxtea_etm_seal_into(&ctx, input, SIZE_MAX, nonce, out, SIZE_MAX, &n));
    txxtea_etm_ctx_clear(&ctx);
#elif defined(PROJECT_F)
    if (SIZE_MAX == UINT32_MAX)
        assert(!txxtea_etm_aad_seal_into(&ctx, input, SIZE_MAX/2, input, SIZE_MAX/2, nonce, out, SIZE_MAX, &n));
    txxtea_etm_aad_ctx_clear(&ctx);
#elif defined(PROJECT_D)
    if (SIZE_MAX == UINT32_MAX) {
        uint8_t *p = NULL; assert(!txxtea_etm_seal(input, SIZE_MAX, key, &p, &n));
    }
#endif
    puts("ASan/UBSan: selected project, 512 lengths PASS");
    return 0;
}
