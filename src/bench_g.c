// bench_g.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif

#include "txxtea128_h.h"

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

static int popcnt8(uint8_t x) {
    int c = 0;
    for (int i = 0; i < 8; i++) c += (x >> i) & 1;
    return c;
}

static size_t bit_diff(const uint8_t *a, const uint8_t *b, size_t n) {
    size_t diff = 0;
    for (size_t i = 0; i < n; i++) diff += (size_t)popcnt8((uint8_t)(a[i] ^ b[i]));
    return diff;
}

static uint8_t *enc_alloc(const uint8_t *pt, size_t n,
                          const uint8_t key[16], const uint8_t nonce12[12]) {
    uint8_t *ct = (uint8_t*)malloc(n);
    if (!ct) return NULL;
    memcpy(ct, pt, n);
    txxtea128_h_ctr_xor(ct, n, key, nonce12);
    return ct;
}

static uint8_t *dec_alloc(const uint8_t *ct, size_t n,
                          const uint8_t key[16], const uint8_t nonce12[12]) {
    uint8_t *pt = (uint8_t*)malloc(n);
    if (!pt) return NULL;
    memcpy(pt, ct, n);
    txxtea128_h_ctr_xor(pt, n, key, nonce12);
    return pt;
}

static double pt_flip_effect_once(size_t n, const uint8_t key[16], const uint8_t nonce12[12]) {
    uint8_t *pt = (uint8_t*)malloc(n);
    fill_rand(pt, n);

    uint8_t *ct1 = enc_alloc(pt, n, key, nonce12);
    pt[0] ^= 0x01;
    uint8_t *ct2 = enc_alloc(pt, n, key, nonce12);

    size_t changed_bits = bit_diff(ct1, ct2, n);
    double pct = 100.0 * (double)changed_bits / (double)(n * 8);

    free(pt); free(ct1); free(ct2);
    return pct;
}

static double nonce_flip_effect_once(size_t n, const uint8_t key[16], const uint8_t nonce12[12]) {
    uint8_t *pt = (uint8_t*)malloc(n);
    fill_rand(pt, n);

    uint8_t nonce2[12];
    memcpy(nonce2, nonce12, 12);
    nonce2[0] ^= 0x01;

    uint8_t *ct1 = enc_alloc(pt, n, key, nonce12);
    uint8_t *ct2 = enc_alloc(pt, n, key, nonce2);

    size_t changed_bits = bit_diff(ct1, ct2, n);
    double pct = 100.0 * (double)changed_bits / (double)(n * 8);

    free(pt); free(ct1); free(ct2);
    return pct;
}

static double key_flip_effect_once(size_t n, const uint8_t key[16], const uint8_t nonce12[12]) {
    uint8_t *pt = (uint8_t*)malloc(n);
    fill_rand(pt, n);

    uint8_t key2[16];
    memcpy(key2, key, 16);
    key2[0] ^= 0x01;

    uint8_t *ct1 = enc_alloc(pt, n, key, nonce12);
    uint8_t *ct2 = enc_alloc(pt, n, key2, nonce12);

    size_t changed_bits = bit_diff(ct1, ct2, n);
    double pct = 100.0 * (double)changed_bits / (double)(n * 8);

    free(pt); free(ct1); free(ct2);
    return pct;
}

int main(void) {
    srand(12345);

    uint8_t key[16], nonce12[12];
    fill_rand(key, 16);
    fill_rand(nonce12, 12);

    size_t sizes[] = {16, 32, 64, 128, 256, 1024, 4096};

    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++) {
        size_t n = sizes[si];

        const int iters = 400;
        uint64_t enc_ns = 0, dec_ns = 0;
        int ok_all = 1;

        for (int i = 0; i < iters; i++) {
            uint8_t *pt = (uint8_t*)malloc(n);
            fill_rand(pt, n);

            uint64_t t0 = ns_now();
            uint8_t *ct = enc_alloc(pt, n, key, nonce12);
            uint64_t t1 = ns_now();
            uint8_t *dec = dec_alloc(ct, n, key, nonce12);
            uint64_t t2 = ns_now();

            enc_ns += (t1 - t0);
            dec_ns += (t2 - t1);

            if (memcmp(dec, pt, n) != 0) ok_all = 0;

            free(pt); free(ct); free(dec);
        }

        const int reps = 200;
        double pt_sum = 0.0, nonce_sum = 0.0, key_sum = 0.0;
        for (int i = 0; i < reps; i++) {
            pt_sum += pt_flip_effect_once(n, key, nonce12);
            nonce_sum += nonce_flip_effect_once(n, key, nonce12);
            key_sum += key_flip_effect_once(n, key, nonce12);
        }

        printf("G-H n=%5zu  enc=%8.1f ns/op  dec=%8.1f ns/op  ok=%d  "
               "ptflip=%6.2f%%  nonceflip=%6.2f%%  keyflip=%6.2f%%\n",
               n,
               (double)enc_ns / iters,
               (double)dec_ns / iters,
               ok_all,
               pt_sum / reps,
               nonce_sum / reps,
               key_sum / reps);
    }
    return 0;
}
