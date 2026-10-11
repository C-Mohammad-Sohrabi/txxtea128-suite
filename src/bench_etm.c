// bench_etm.c
#include "txxtea_etm.h"
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

    size_t sizes[] = {16, 32, 64, 128, 256, 1024, 4096, 16384};

    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++) {
        size_t n = sizes[si];
        uint8_t *pt = (uint8_t*)malloc(n);
        if (!pt) return 1;
        fill_rand(pt, n);

        const int iters = 300;
        uint64_t seal_ns = 0, open_ns = 0;
        int ok_all = 1;

        for (int i = 0; i < iters; i++) {
            uint8_t *sealed = NULL;
            size_t sealed_len = 0;

            uint64_t t0 = ns_now();
            int ok1 = txxtea_etm_seal(pt, n, master, &sealed, &sealed_len);
            uint64_t t1 = ns_now();

            uint8_t *out = NULL;
            size_t out_len = 0;
            int ok2 = txxtea_etm_open(sealed, sealed_len, master, &out, &out_len);
            uint64_t t2 = ns_now();

            seal_ns += (t1 - t0);
            open_ns += (t2 - t1);

            if (!ok1 || !ok2 || out_len != n || memcmp(out, pt, n) != 0) ok_all = 0;

            free(sealed);
            free(out);
        }

        printf("ETM n=%6zu  seal=%10.1f ns/op  open=%10.1f ns/op  ok=%d\n",
               n, (double)seal_ns / iters, (double)open_ns / iters, ok_all);

        free(pt);
    }

    return 0;
}
