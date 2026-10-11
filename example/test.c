#ifdef _MSC_VER
#pragma comment(lib, "xxtea.lib")
#endif

#include <stdio.h>
#include <string.h>
#include <xxtea.h>
#include "base64.h"

int main(void) {
    const char *text = "Hello World! 你好，中国！";
    const char *key = "1234567890";
    size_t ciphertext_len = 0, plaintext_len = 0;
    unsigned char *ciphertext = xxtea_encrypt(text, strlen(text), key, &ciphertext_len);
    if (!ciphertext) return 1;
    char *encoded = base64_encode(ciphertext, ciphertext_len);
    if (!encoded) { free(ciphertext); return 1; }
    char *plaintext = xxtea_decrypt(ciphertext, ciphertext_len, key, &plaintext_len);
    int ok = plaintext && plaintext_len == strlen(text) &&
             memcmp(text, plaintext, plaintext_len) == 0;
    printf("%s\n%s\n", encoded, ok ? "success!" : "fail!");
    free(ciphertext);
    free(plaintext);
    free(encoded);
    return ok ? 0 : 1;
}
