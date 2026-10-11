/**********************************************************\
|                                                          |
| base64.c                                                 |
|                                                          |
| Base64 library for C.                                    |
|                                                          |
| Code Authors: Chen fei <cf850118@163.com>                |
|               Ma Bingyao <mabingyao@gmail.com>           |
| LastModified: Mar 3, 2015                                |
|                                                          |
\**********************************************************/

#include <string.h>
#include <stdint.h>
#include "base64.h"

static const char Base64EncodeChars[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static const signed char Base64DecodeChars[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

char * base64_encode(const unsigned char * data, size_t len) {
    char *out, *pos;
    const unsigned char *in = data;
    size_t i, quot, rem;
    int c;

    if (!data || !len || len / 3 + (len % 3 != 0) > (SIZE_MAX - 1) / 4) return NULL;

    quot = len / 3;
    rem  = len % 3;
    out = (char *)malloc((quot + (rem ? 1 : 0)) * 4 + 1);
    if (!out) return NULL;

    pos = out;

    for (i = 0; i < quot; i++) {
        c  = (0x000000ff & *in++) << 16;
        c |= (0x000000ff & *in++) << 8;
        c |=  0x000000ff & *in++;
        *pos++ = Base64EncodeChars[c >> 18];
        *pos++ = Base64EncodeChars[c >> 12 & 0x3f];
        *pos++ = Base64EncodeChars[c >> 6  & 0x3f];
        *pos++ = Base64EncodeChars[c & 0x3f];
    }

    if (rem == 1) {
        c = 0x000000ff & *in++;
        *pos++ = Base64EncodeChars[c >> 2];
        *pos++ = Base64EncodeChars[(c & 0x03) << 4];
        *pos++ = '=';
        *pos++ = '=';
    }
    else if (rem == 2) {
        c  = (0x000000ff & *in++) << 8;
        c |=  0x000000ff & *in++;
        *pos++ = Base64EncodeChars[c >> 10];
        *pos++ = Base64EncodeChars[c >> 4 & 0x3f];
        *pos++ = Base64EncodeChars[(c & 0x0f) << 2];
        *pos++ = '=';
    }

    *pos = '\0';

    return out;
}

unsigned char * base64_decode(const char *data, size_t *out_len) {
    size_t len, i, n = 0;
    unsigned char *out;
    if (!out_len) return NULL;
    *out_len = 0;
    if (!data) return NULL;
    len = strlen(data);
    if (!len || len % 4) return NULL;
    out = (unsigned char *)malloc(len / 4 * 3 + 1);
    if (!out) return NULL;
    for (i = 0; i < len; i += 4) {
        unsigned char a = (unsigned char)data[i], b = (unsigned char)data[i+1];
        unsigned char c = (unsigned char)data[i+2], d = (unsigned char)data[i+3];
        int x, y, z = 0, w = 0;
        if (a >= 128 || b >= 128 || c >= 128 || d >= 128) goto invalid;
        x = Base64DecodeChars[a]; y = Base64DecodeChars[b];
        if (x < 0 || y < 0) goto invalid;
        if (c == '=') {
            if (d != '=' || i + 4 != len || (y & 15)) goto invalid;
        } else {
            z = Base64DecodeChars[c];
            if (z < 0) goto invalid;
            if (d == '=') {
                if (i + 4 != len || (z & 3)) goto invalid;
            } else {
                w = Base64DecodeChars[d];
                if (w < 0) goto invalid;
            }
        }
        out[n++] = (unsigned char)((x << 2) | (y >> 4));
        if (c != '=') out[n++] = (unsigned char)((y << 4) | (z >> 2));
        if (d != '=') out[n++] = (unsigned char)((z << 6) | w);
    }
    out[n] = 0;
    *out_len = n;
    return out;
invalid:
    free(out);
    return NULL;
}
