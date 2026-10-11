/* Exercise each allocation in the base API, including its output malloc. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static int alloc_index, fail_at;
static void *failing_malloc(size_t n) {
    if (++alloc_index == fail_at) return NULL;
    return malloc(n);
}
static void *failing_calloc(size_t n, size_t size) {
    if (++alloc_index == fail_at) return NULL;
    return calloc(n, size);
}
#define malloc failing_malloc
#define calloc failing_calloc
#include "../src/xxtea.c"
#undef malloc
#undef calloc
int main(void) {
    uint8_t key[16] = {0};size_t n=0, m=0;
    fail_at=0;alloc_index=0;
    void *ct=xxtea_encrypt_raw("hello",5,key,&n);assert(ct);
    for (int i=1;i<=3;i++) {
        alloc_index=0;fail_at=i;m=999;
        assert(!xxtea_encrypt_raw("hello",5,key,&m) && m==0);
        alloc_index=0;fail_at=i;m=999;
        assert(!xxtea_decrypt_raw(ct,n,key,&m) && m==0);
    }
    free(ct);puts("Base allocation failures: all 6 paths PASS");return 0;
}
