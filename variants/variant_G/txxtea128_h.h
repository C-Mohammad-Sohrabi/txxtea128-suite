// txxtea128_h.h
#ifndef TXXTEA128_H_H
#define TXXTEA128_H_H

#include <stddef.h>
#include <stdint.h>

// Hardened tweakable XXTEA-128 block cipher.
//
// Fixes the weak spots of variants A/B/C:
//   1. Rounds raised from 19 to 32 (safety margin; 19 is the bare minimum
//      from the original 6+52/n formula).
//   2. Pre/post whitening so the key+tweak affect the data path before the
//      first round and after the last round (not only via round-internal MX).
//   3. A feedback key/tweak schedule: each round-key word is derived from an
//      evolving state that mixes *all* key/tweak words (the key/tweak word
//      selection rotates with the round index) with rotations, the running
//      sum, and 32-bit additions for nonlinearity. Unlike variant C, round
//      keys are not merely linear combinations of k and t.
//
// The schedule depends only on (key, tweak, round number), never on the
// data block, so encryption and decryption compute identical round keys.
//
// NOTE: this is still a custom, unvetted construction. Avalanche ~50% is
// necessary but not sufficient for security. For real secrets prefer a
// vetted cipher (AES-CTR, ChaCha20) behind the variant_D/E/F ETM wrapper.

void txxtea128_h_encrypt_block(uint8_t out[16], const uint8_t in[16],
                               const uint8_t key[16], const uint8_t tweak[16]);

void txxtea128_h_decrypt_block(uint8_t out[16], const uint8_t in[16],
                               const uint8_t key[16], const uint8_t tweak[16]);

// CTR-xor using the tweakable block cipher:
// tweak per-block = nonce12 || counter_le32, keystream = E_{key,tweak}(0^128)
void txxtea128_h_ctr_xor(uint8_t *data, size_t len,
                         const uint8_t key[16], const uint8_t nonce12[12]);

#endif