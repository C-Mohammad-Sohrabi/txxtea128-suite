// demo_aad.c
#include "txxtea_etm_aad.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void fill_key(uint8_t *k, size_t n) {
    for (size_t i = 0; i < n; i++) k[i] = (uint8_t)(i * 7 + 3);
}

int main(void) {
    uint8_t master[32];
    fill_key(master, 32);

    txxtea_etm_aad_ctx ctx;
    if (!txxtea_etm_aad_ctx_init(&ctx, master)) {
        printf("ctx init failed\n");
        return 1;
    }

    const char *msg = "hello with AAD";
    const uint8_t *pt = (const uint8_t*)msg;
    size_t pt_len = strlen(msg);

    const uint8_t aad[] = {0x01,0x02,0x03,0x04, 0xAA,0xBB}; // مثال
    size_t aad_len = sizeof(aad);

    uint8_t nonce[12] = {0};
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0x10 + i);

    uint8_t out[1024];
    size_t out_len = 0;

    if (!txxtea_etm_aad_seal_into(&ctx, pt, pt_len, aad, aad_len, nonce, out, sizeof(out), &out_len)) {
        printf("seal failed\n");
        return 1;
    }
    printf("sealed_len=%zu\n", out_len);

    uint8_t pt2[256];
    uint8_t aad2[256];
    size_t pt2_len = 0, aad2_len = 0;

    if (!txxtea_etm_aad_open_into(&ctx, out, out_len, pt2, sizeof(pt2), &pt2_len, aad2, sizeof(aad2), &aad2_len)) {
        printf("open failed\n");
        return 1;
    }
    printf("opened_txt=%.*s\n", (int)pt2_len, (char*)pt2);
    printf("aad_len=%zu  aad_first=%02x\n", aad2_len, aad2_len?aad2[0]:0);

    // tamper AAD: flip one bit in aad area => should fail
    out[TXXTEA_HEADER_LEN + 1] ^= 0x01;
    size_t pt3_len=0, aad3_len=0;
    int ok = txxtea_etm_aad_open_into(&ctx, out, out_len, pt2, sizeof(pt2), &pt3_len, aad2, sizeof(aad2), &aad3_len);
    printf("tamper_aad_open_ok=%d (expected 0)\n", ok);

    return 0;
}
