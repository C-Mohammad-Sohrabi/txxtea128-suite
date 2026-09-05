// demo_etm.c
#include "txxtea_etm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    // master key (32 bytes) - نمونه
    uint8_t master[32];
    for (int i = 0; i < 32; i++) master[i] = (uint8_t)(i * 3 + 1);

    const char *msg = "hello from txxtea + CTR + HMAC(SHA-256)";
    const uint8_t *pt = (const uint8_t*)msg;
    size_t pt_len = strlen(msg);

    uint8_t *sealed = NULL;
    size_t sealed_len = 0;

    if (!txxtea_etm_seal(pt, pt_len, master, &sealed, &sealed_len)) {
        printf("seal failed\n");
        return 1;
    }

    printf("sealed_len=%zu\n", sealed_len);
    printf("sealed_hex=");
    hex(sealed, sealed_len);

    uint8_t *opened = NULL;
    size_t opened_len = 0;

    if (!txxtea_etm_open(sealed, sealed_len, master, &opened, &opened_len)) {
        printf("open failed\n");
        free(sealed);
        return 1;
    }

    printf("opened_len=%zu\n", opened_len);
    printf("opened_txt=%.*s\n", (int)opened_len, (char*)opened);

    free(opened);

    // tamper test: flip one bit in ciphertext (should fail)
    sealed[25] ^= 0x01; // somewhere after header
    uint8_t *opened2 = NULL;
    size_t opened2_len = 0;
    int ok = txxtea_etm_open(sealed, sealed_len, master, &opened2, &opened2_len);
    printf("tamper_open_ok=%d (expected 0)\n", ok);
    if (ok) free(opened2);

    free(sealed);
    return 0;
}
