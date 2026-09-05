// txxtea_etm.h
#ifndef TXXTEA_ETM_H
#define TXXTEA_ETM_H

#include <stddef.h>
#include <stdint.h>

//
// output format (binary):
//  3 bytes  magic = "TX1"
//  1 byte   version = 1
//  12 bytes nonce
//  4 bytes  ciphertext_len (LE uint32)
//  N bytes  ciphertext
//  32 bytes tag = HMAC-SHA256( mac_key, header||ciphertext )
//
// Returns 1 on success, 0 on failure.

int txxtea_etm_seal(const uint8_t *pt, size_t pt_len,
                    const uint8_t master_key[32],
                    uint8_t **out, size_t *out_len);

int txxtea_etm_open(const uint8_t *in, size_t in_len,
                    const uint8_t master_key[32],
                    uint8_t **pt, size_t *pt_len);

#endif
