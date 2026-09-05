// txxtea128_rs.h
#ifndef TXXTEA128_RS_H
#define TXXTEA128_RS_H

#include <stddef.h>
#include <stdint.h>

void txxtea128_rs_encrypt_block(uint8_t out[16], const uint8_t in[16],
                                const uint8_t key[16], const uint8_t tweak[16]);

void txxtea128_rs_decrypt_block(uint8_t out[16], const uint8_t in[16],
                                const uint8_t key[16], const uint8_t tweak[16]);

void txxtea128_rs_ctr_xor(uint8_t *data, size_t len,
                          const uint8_t key[16], const uint8_t nonce12[12]);

#endif
