// txxtea128.c
#include "txxtea128.h"
#include <string.h>
#include "../../crypto_util.h"

#define DELTA 0x9e3779b9u

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

// Tweak-injected mixing (Variant B1-a enabled)
static uint32_t mx_t(uint32_t sum, uint32_t y, uint32_t z,
                     uint32_t p, uint32_t e,
                     const uint32_t k[4], const uint32_t t[4]) {

    uint32_t base =
        (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
      ^ ((sum ^ y) + (k[(p & 3u) ^ e] ^ z));

    // Option B1-a (ACTIVE):
    return base ^ t[p & 3u];
}

void txxtea128_encrypt_block(uint8_t out[16], const uint8_t in[16],
                            const uint8_t key[16], const uint8_t tweak[16]) {
    uint32_t v[4], k[4], t[4];

    for (int i = 0; i < 4; i++) {
        v[i] = load_le32(in + 4*i);
        k[i] = load_le32(key + 4*i);
        t[i] = load_le32(tweak + 4*i);
    }

    uint32_t rounds = 19;
    uint32_t sum = 0;

    while (rounds--) {
        sum += DELTA;
        uint32_t e = (sum >> 2) & 3u;

        uint32_t y, z;

        z = v[3]; y = v[1];
        v[0] += mx_t(sum, y, z, 0, e, k, t);

        z = v[0]; y = v[2];
        v[1] += mx_t(sum, y, z, 1, e, k, t);

        z = v[1]; y = v[3];
        v[2] += mx_t(sum, y, z, 2, e, k, t);

        z = v[2]; y = v[0];
        v[3] += mx_t(sum, y, z, 3, e, k, t);
    }

    for (int i = 0; i < 4; i++) store_le32(out + 4*i, v[i]);
    xxtea_secure_zero(v, sizeof(v));
    xxtea_secure_zero(k, sizeof(k));
    xxtea_secure_zero(t, sizeof(t));
}

void txxtea128_decrypt_block(uint8_t out[16], const uint8_t in[16],
                            const uint8_t key[16], const uint8_t tweak[16]) {
    uint32_t v[4], k[4], t[4];

    for (int i = 0; i < 4; i++) {
        v[i] = load_le32(in + 4*i);
        k[i] = load_le32(key + 4*i);
        t[i] = load_le32(tweak + 4*i);
    }

    uint32_t rounds = 19;
    uint32_t sum = DELTA * rounds;

    while (rounds--) {
        uint32_t e = (sum >> 2) & 3u;

        uint32_t y, z;

        y = v[0]; z = v[2];
        v[3] -= mx_t(sum, y, z, 3, e, k, t);

        y = v[3]; z = v[1];
        v[2] -= mx_t(sum, y, z, 2, e, k, t);

        y = v[2]; z = v[0];
        v[1] -= mx_t(sum, y, z, 1, e, k, t);

        y = v[1]; z = v[3];
        v[0] -= mx_t(sum, y, z, 0, e, k, t);

        sum -= DELTA;
    }

    for (int i = 0; i < 4; i++) store_le32(out + 4*i, v[i]);
    xxtea_secure_zero(v, sizeof(v));
    xxtea_secure_zero(k, sizeof(k));
    xxtea_secure_zero(t, sizeof(t));
}

int txxtea128_ctr_xor(uint8_t *data, size_t len,
                       const uint8_t key[16], const uint8_t nonce12[12]) {
    if ((!data && len) || !key || !nonce12 || !xxtea_ctr_length_ok(len)) return 0;
    uint32_t counter = 0;
    uint8_t tweak[16];
    uint8_t ks[16];

    memcpy(tweak, nonce12, 12);

    size_t off = 0;
    while (off < len) {
        // tweak = nonce||counter
        store_le32(tweak + 12, counter);
        counter++;

        // keystream = E_{key,tweak}(0^128)
        uint8_t zero[16] = {0};
        txxtea128_encrypt_block(ks, zero, key, tweak);

        size_t take = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < take; i++) data[off + i] ^= ks[i];
        off += take;
    }

    xxtea_secure_zero(tweak, sizeof(tweak));
    xxtea_secure_zero(ks, sizeof(ks));
    return 1;
}
