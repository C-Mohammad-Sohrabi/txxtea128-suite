// bench_etm_ctx.c
#include "txxtea_etm_ctx.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif

static uint64_t ns_now(void) {
#if defined(_WIN32)
    static LARGE_INTEGER freq;
    LARGE_INTEGER cnt;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (uint64_t)((cnt.QuadPart * 1000000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static void fill_rand(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rand();
}

int main(void) {
    srand(12345);

    uint8_t master[32];
    fill_rand(master, sizeof(master));

    txxtea_etm_ctx ctx;
    if (!txxtea_etm_ctx_init(&ctx, master)) {
        printf("ctx_init failed\n");
        return 1;
    }

    // fixed nonce for benchmarking (so we measure crypto cost, not RNG)
    uint8_t nonce[12];
    fill_rand(nonce, sizeof(nonce));

    size_t sizes[] = {16, 32, 64, 128, 256, 1024, 4096, 16384};

    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++) {
        size_t n = sizes[si];

        uint8_t *pt = (uint8_t*)malloc(n);
        uint8_t *out = (uint8_t*)malloc(TXXTEA_HEADER_LEN + n + TXXTEA_TAG_LEN);
        uint8_t *dec = (uint8_t*)malloc(n ? n : 1);
        if (!pt || !out || !dec) return 1;

        fill_rand(pt, n);

        const int iters = 2000;
        uint64_t seal_ns = 0, open_ns = 0;
        int ok_all = 1;

        for (int i = 0; i < iters; i++) {
            size_t out_len = 0;
            size_t dec_len = 0;

            uint64_t t0 = ns_now();
            int ok1 = txxtea_etm_seal_into(&ctx, pt, n, nonce, out,
                                           TXXTEA_HEADER_LEN + n + TXXTEA_TAG_LEN, &out_len);
            uint64_t t1 = ns_now();
            int ok2 = txxtea_etm_open_into(&ctx, out, out_len, dec, n, &dec_len);
            uint64_t t2 = ns_now();

            seal_ns += (t1 - t0);
            open_ns += (t2 - t1);

            if (!ok1 || !ok2 || dec_len != n || memcmp(dec, pt, n) != 0) ok_all = 0;
        }

        printf("ETM-CTX n=%6zu  seal=%10.1f ns/op  open=%10.1f ns/op  ok=%d\n",
               n, (double)seal_ns / iters, (double)open_ns / iters, ok_all);

        free(pt);
        free(out);
        free(dec);
    }

    return 0;
}
