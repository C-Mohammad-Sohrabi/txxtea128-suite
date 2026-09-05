// bench.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#endif

// These are provided by the xxtea-c library.
// You link bench.c with xxtea.c when compiling.
unsigned char *xxtea_encrypt(const unsigned char *data, size_t len,
                            const unsigned char *key, size_t *out_len);
unsigned char *xxtea_decrypt(const unsigned char *data, size_t len,
                            const unsigned char *key, size_t *out_len);

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

static int round_trip_once(size_t n, const uint8_t key[16]) {
    uint8_t *pt = (uint8_t*)malloc(n);
    if (!pt) return 0;
    fill_rand(pt, n);

    size_t ct_len = 0, dec_len = 0;
    unsigned char *ct = xxtea_encrypt(pt, n, key, &ct_len);
    if (!ct) { free(pt); return 0; }

    unsigned char *dec = xxtea_decrypt(ct, ct_len, key, &dec_len);
    if (!dec) { free(pt); free(ct); return 0; }

    int ok = (dec_len == n) && (memcmp(dec, pt, n) == 0);

    free(pt);
    free(ct);
    free(dec);
    return ok;
}

// Avalanche test: flip one bit of plaintext and measure changed bits in ciphertext.
static double avalanche_once(size_t n, const uint8_t key[16]) {
    uint8_t *pt = (uint8_t*)malloc(n);
    if (!pt) return -1.0;
    fill_rand(pt, n);

    size_t ct1_len = 0, ct2_len = 0;

    unsigned char *ct1 = xxtea_encrypt(pt, n, key, &ct1_len);
    if (!ct1) { free(pt); return -1.0; }

    // Flip a single bit (bit 0 of byte 0)
    pt[0] ^= 0x01;

    unsigned char *ct2 = xxtea_encrypt(pt, n, key, &ct2_len);
    if (!ct2) { free(pt); free(ct1); return -1.0; }

    // Compare up to the minimum length (normally equal for fixed n)
    size_t m = (ct1_len < ct2_len) ? ct1_len : ct2_len;

    size_t changed_bits = bit_diff((const uint8_t*)ct1, (const uint8_t*)ct2, m);
    size_t total_bits   = m * 8;

    free(pt);
    free(ct1);
    free(ct2);

    return 100.0 * (double)changed_bits / (double)total_bits;
}

int main(void) {
    srand(12345);

    uint8_t key[16];
    fill_rand(key, sizeof(key));

    size_t sizes[] = {16, 32, 64, 128, 256, 1024, 4096};

    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); si++) {
        size_t n = sizes[si];

        // Timing benchmark
        const int iters = 200;
        uint64_t enc_ns = 0, dec_ns = 0;
        int ok_all = 1;

        for (int i = 0; i < iters; i++) {
            uint8_t *pt = (uint8_t*)malloc(n);
            if (!pt) return 1;
            fill_rand(pt, n);

            size_t ct_len = 0, dec_len = 0;

            uint64_t t0 = ns_now();
            unsigned char *ct = xxtea_encrypt(pt, n, key, &ct_len);
            uint64_t t1 = ns_now();
            unsigned char *dec = xxtea_decrypt(ct, ct_len, key, &dec_len);
            uint64_t t2 = ns_now();

            enc_ns += (t1 - t0);
            dec_ns += (t2 - t1);

            int ok = (dec_len == n) && (memcmp(dec, pt, n) == 0);
            if (!ok) ok_all = 0;

            free(pt);
            free(ct);
            free(dec);
        }

        // Avalanche benchmark
        const int av_iters = 200;
        double av_sum = 0.0;
        for (int i = 0; i < av_iters; i++) {
            double p = avalanche_once(n, key);
            av_sum += p;
        }

        printf("n=%5zu  enc=%8.1f ns/op  dec=%8.1f ns/op  ok=%d  avalanche=%6.2f %%\n",
               n,
               (double)enc_ns / iters,
               (double)dec_ns / iters,
               ok_all,
               av_sum / av_iters);
    }

    printf("sanity=%d\n", round_trip_once(37, key));
    return 0;
}
