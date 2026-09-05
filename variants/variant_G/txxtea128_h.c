// txxtea128_h.c
#include "txxtea128_h.h"
#include <string.h>

#define DELTA 0x9e3779b9u
#define ROUNDS 32

static uint32_t load_le32(const uint8_t b[4]) {
    return (uint32_t)b[0]
        | ((uint32_t)b[1] << 8)
        | ((uint32_t)b[2] << 16)
        | ((uint32_t)b[3] << 24);
}

static void store_le32(uint8_t b[4], uint32_t x) {
    b[0] = (uint8_t)(x);
    b[1] = (uint8_t)(x >> 8);
    b[2] = (uint8_t)(x >> 16);
    b[3] = (uint8_t)(x >> 24);
}

static uint32_t rotl32(uint32_t x, unsigned r) {
    r &= 31u;
    return (x << r) | (x >> ((32u - r) & 31u));
}

// XXTEA mixing term; round keys come from the schedule rk[].
static uint32_t mx(uint32_t sum, uint32_t y, uint32_t z,
                   uint32_t p, uint32_t e, const uint32_t rk[4]) {
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
         ^ ((sum ^ y) + (rk[(p & 3u) ^ e] ^ z));
}

// Feedback key+tweak schedule.
//
// Variant C's schedule is a linear combination of k and t (XOR/rot/const),
// and variant B only XORs the tweak into the last step of the mix term.
// Here each round-key word is produced from an evolving state s[4] that
// mixes ALL key/tweak words: the (key,tweak) word feeding slot p rotates
// with the round index r, and s feeds forward with a 32-bit addition
// (nonlinear) plus a rotation. Two state words are then combined per round
// key, so after a few rounds every round key depends on every key and tweak
// word through the additions, not just XORs.
//
// Important: the state is seeded from the TWEAK only, and key words are
// injected per round. Injecting a key word that is already inside the state
// (e.g. seeding s[p]=k[p]^t[p] and then XORing k[p] back in at round 0)
// cancels that key word out entirely. With a tweak-only seed, k[p] enters
// slot p at round r=p and cannot cancel itself.
//
// Deterministic in (key, tweak, r) only -> identical in enc and dec.
static void make_round_keys(uint32_t rk[ROUNDS][4], const uint32_t k[4], const uint32_t t[4]) {
    uint32_t s[4];
    uint32_t sum = 0;

    for (int i = 0; i < 4; i++) s[i] = t[i] ^ rotl32(t[(i + 1) & 3u], 3);

    for (uint32_t r = 0; r < ROUNDS; r++) {
        sum += DELTA;

        for (int p = 0; p < 4; p++) {
            uint32_t kv = k[(p + r) & 3u];
            uint32_t tv = t[(p + r) & 3u] ^ sum;
            s[p] = rotl32(s[p] ^ kv, 9) + tv;   // nonlinear feedback
        }

        for (int p = 0; p < 4; p++) {
            rk[r][p] = s[p] ^ rotl32(s[(p + 1) & 3u], 11);  // cross-word mix
        }
    }

    memset(s, 0, sizeof(s));
}

static void encrypt_core(uint32_t v[4], const uint32_t rk[ROUNDS][4]) {
    // pre-whitening
    for (int p = 0; p < 4; p++) {
        v[p] ^= rk[0][p] ^ rotl32(rk[0][(p + 1) & 3u], 5);
    }

    uint32_t sum = 0;
    for (uint32_t r = 0; r < ROUNDS; r++) {
        sum += DELTA;
        uint32_t e = (sum >> 2) & 3u;
        uint32_t y, z;

        z = v[3]; y = v[1];
        v[0] += mx(sum, y, z, 0, e, rk[r]);

        z = v[0]; y = v[2];
        v[1] += mx(sum, y, z, 1, e, rk[r]);

        z = v[1]; y = v[3];
        v[2] += mx(sum, y, z, 2, e, rk[r]);

        z = v[2]; y = v[0];
        v[3] += mx(sum, y, z, 3, e, rk[r]);
    }

    // post-whitening (rotation differs from pre so the two don't cancel)
    for (int p = 0; p < 4; p++) {
        v[p] ^= rk[ROUNDS - 1][p] ^ rotl32(rk[ROUNDS - 1][(p + 1) & 3u], 13);
    }
}

static void decrypt_core(uint32_t v[4], const uint32_t rk[ROUNDS][4]) {
    // undo post-whitening
    for (int p = 0; p < 4; p++) {
        v[p] ^= rk[ROUNDS - 1][p] ^ rotl32(rk[ROUNDS - 1][(p + 1) & 3u], 13);
    }

    uint32_t sum = DELTA * ROUNDS;
    for (uint32_t rr = 0; rr < ROUNDS; rr++) {
        uint32_t r = (ROUNDS - 1u) - rr;
        uint32_t e = (sum >> 2) & 3u;
        uint32_t y, z;

        y = v[0]; z = v[2];
        v[3] -= mx(sum, y, z, 3, e, rk[r]);

        y = v[3]; z = v[1];
        v[2] -= mx(sum, y, z, 2, e, rk[r]);

        y = v[2]; z = v[0];
        v[1] -= mx(sum, y, z, 1, e, rk[r]);

        y = v[1]; z = v[3];
        v[0] -= mx(sum, y, z, 0, e, rk[r]);

        sum -= DELTA;
    }

    // undo pre-whitening
    for (int p = 0; p < 4; p++) {
        v[p] ^= rk[0][p] ^ rotl32(rk[0][(p + 1) & 3u], 5);
    }
}

void txxtea128_h_encrypt_block(uint8_t out[16], const uint8_t in[16],
                               const uint8_t key[16], const uint8_t tweak[16]) {
    uint32_t v[4], k[4], t[4];
    uint32_t rk[ROUNDS][4];

    for (int i = 0; i < 4; i++) {
        v[i] = load_le32(in + 4*i);
        k[i] = load_le32(key + 4*i);
        t[i] = load_le32(tweak + 4*i);
    }

    make_round_keys(rk, k, t);
    encrypt_core(v, rk);

    for (int i = 0; i < 4; i++) store_le32(out + 4*i, v[i]);

    memset(rk, 0, sizeof(rk));
    memset(k, 0, sizeof(k));
    memset(t, 0, sizeof(t));
}

void txxtea128_h_decrypt_block(uint8_t out[16], const uint8_t in[16],
                               const uint8_t key[16], const uint8_t tweak[16]) {
    uint32_t v[4], k[4], t[4];
    uint32_t rk[ROUNDS][4];

    for (int i = 0; i < 4; i++) {
        v[i] = load_le32(in + 4*i);
        k[i] = load_le32(key + 4*i);
        t[i] = load_le32(tweak + 4*i);
    }

    make_round_keys(rk, k, t);
    decrypt_core(v, rk);

    for (int i = 0; i < 4; i++) store_le32(out + 4*i, v[i]);

    memset(rk, 0, sizeof(rk));
    memset(k, 0, sizeof(k));
    memset(t, 0, sizeof(t));
}

void txxtea128_h_ctr_xor(uint8_t *data, size_t len,
                         const uint8_t key[16], const uint8_t nonce12[12]) {
    uint32_t counter = 0;
    uint8_t tweak[16];
    uint8_t ks[16];

    memcpy(tweak, nonce12, 12);

    size_t off = 0;
    while (off < len) {
        // tweak = nonce || counter_le32
        store_le32(tweak + 12, counter);
        counter++;

        // keystream = E_{key,tweak}(0^128)
        uint8_t zero[16] = {0};
        txxtea128_h_encrypt_block(ks, zero, key, tweak);

        size_t take = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < take; i++) data[off + i] ^= ks[i];
        off += take;
    }

    memset(tweak, 0, sizeof(tweak));
    memset(ks, 0, sizeof(ks));
}