#ifndef XXTEA_CRYPTO_UTIL_H
#define XXTEA_CRYPTO_UTIL_H
#include <stddef.h>
#include <stdint.h>
/* Volatile stores prevent dead-store elimination of these explicit wipes.
 * This does not claim to erase register copies or the entire call stack. */
static inline void xxtea_secure_zero(void *ptr, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (n--) *p++ = 0;
}
/* At most 2^32 distinct 16-byte counter blocks, with counter starting at 0. */
static inline int xxtea_ctr_length_ok(size_t len) {
    return (uint64_t)(len / 16) + (len % 16 != 0) <= UINT64_C(4294967296);
}
#endif
