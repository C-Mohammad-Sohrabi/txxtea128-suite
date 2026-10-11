// txxtea128.h
#ifndef TXXTEA128_H
#define TXXTEA128_H

#include <stddef.h>
#include <stdint.h>

// Tweakable XXTEA-128 block cipher:
// key: 16 bytes
// tweak: 16 bytes (we will derive it from nonce||counter in CTR)
void txxtea128_encrypt_block(uint8_t out[16], const uint8_t in[16],
                            const uint8_t key[16], const uint8_t tweak[16]);

void txxtea128_decrypt_block(uint8_t out[16], const uint8_t in[16],
                            const uint8_t key[16], const uint8_t tweak[16]);

// Returns 1 on success, 0 before modifying data on invalid pointers/length.
// Max length: 2^36 bytes per call. Never reuse key+nonce; calls restart counter at 0.
// CTR-xor using tweakable block cipher:
// tweak per-block = nonce12 || counter_le32  (16 bytes)
int txxtea128_ctr_xor(uint8_t *data, size_t len,
                       const uint8_t key[16], const uint8_t nonce12[12]);

#endif
