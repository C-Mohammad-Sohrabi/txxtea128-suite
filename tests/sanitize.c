#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xxtea.h"
#include "example/base64.h"
#include "variants/variant_A/xxtea128.h"
#include "variants/variant_B/txxtea128.h"
#include "variants/variant_C/txxtea128_rs.h"
#include "variants/variant_G/txxtea128_h.h"
#include "variants/variant_D/txxtea_etm.h"
#include "variants/variant_E/txxtea_etm_ctx.h"
#include "variants/variant_F/txxtea_etm_aad.h"
static uint32_t state=20261010;
static uint8_t next(void){state^=state<<13;state^=state>>17;state^=state<<5;return (uint8_t)state;}
int main(void){
    _Static_assert(TXXTEA_HEADER_LEN == 20, "E header");
    _Static_assert(TXXTEA_AAD_HEADER_LEN == 24, "F header");
    uint8_t key[32]={0}, nonce[16]={0}, input[512], out[1024], pt[1024], aad[1024];
    size_t n, m, an; uint8_t *p=NULL; txxtea_etm_ctx e;txxtea_etm_aad_ctx f;
    assert(txxtea_etm_ctx_init(&e,key));assert(txxtea_etm_aad_ctx_init(&f,key));
    /* This exact two-byte string read overran the old FIXED_KEY memcpy. */
    char *short_key=malloc(2);assert(short_key);strcpy(short_key,"k");
    p=xxtea_encrypt("hello",5,short_key,&n);assert(p);free(p);free(short_key);
    for(size_t len=0;len<sizeof(input);len++){
        for(size_t j=0;j<len;j++)input[j]=next();
        if(len){p=xxtea_encrypt_raw(input,len,key,&n);assert(p);uint8_t *d=xxtea_decrypt_raw(p,n,key,&m);assert(d&&m==len&&!memcmp(d,input,len));free(p);free(d);}
        memcpy(pt,input,len);assert(xxtea128_ctr_xor(pt,len,key,nonce));assert(xxtea128_ctr_xor(pt,len,key,nonce));assert(!memcmp(pt,input,len));
        assert(txxtea128_ctr_xor(pt,len,key,nonce));assert(txxtea128_rs_ctr_xor(pt,len,key,nonce));assert(txxtea128_h_ctr_xor(pt,len,key,nonce));
        assert(txxtea_etm_seal(input,len,key,&p,&n));uint8_t *d=NULL;assert(txxtea_etm_open(p,n,key,&d,&m)&&m==len&&!memcmp(d,input,len));free(p);free(d);
        assert(txxtea_etm_seal_into(&e,input,len,nonce,out,sizeof(out),&n));assert(txxtea_etm_open_into(&e,out,n,pt,sizeof(pt),&m));assert(m==len&&!memcmp(pt,input,len));
        assert(txxtea_etm_aad_seal_into(&f,input,len,input,len%31,nonce,out,sizeof(out),&n));assert(txxtea_etm_aad_open_into(&f,out,n,pt,sizeof(pt),&m,aad,sizeof(aad),&an));assert(m==len&&an==len%31&&!memcmp(pt,input,len));
        if(len){char *b64=base64_encode(input,len);assert(b64);p=base64_decode(b64,&m);assert(p&&m==len&&!memcmp(p,input,len));free(p);free(b64);}
    }
    const char *bad[]={"!!!!","====","AA=A","AA==AAAA","AB==","AAB=","\xff\xff\xff\xff"};
    for(size_t i=0;i<sizeof(bad)/sizeof(*bad);i++){n=77;assert(!base64_decode(bad[i],&n)&&n==0);}
    for(int trial=0;trial<5000;trial++){
        size_t len=next();for(size_t j=0;j<len;j++)input[j]=next();
        p=xxtea_decrypt_raw(input,len,key,&n);free(p);
        assert(!txxtea_etm_open(input,len,key,&p,&n));
        assert(!txxtea_etm_open_into(&e,input,len,pt,sizeof(pt),&m));
        assert(!txxtea_etm_aad_open_into(&f,input,len,pt,sizeof(pt),&m,aad,sizeof(aad),&an));
    }
    /* On a real 32-bit build these exercise pre-allocation arithmetic guards. */
    if(SIZE_MAX==UINT32_MAX){
        assert(!txxtea_etm_seal(input,SIZE_MAX,key,&p,&n));
        assert(!txxtea_etm_seal_into(&e,input,SIZE_MAX,nonce,out,SIZE_MAX,&n));
        assert(!txxtea_etm_aad_seal_into(&f,input,SIZE_MAX/2,input,SIZE_MAX/2,nonce,out,SIZE_MAX,&n));
    }
    txxtea_etm_ctx_clear(&e);txxtea_etm_aad_ctx_clear(&f);
    puts("ASan/UBSan: short string key, 512 lengths, Base64, 5000 malformed inputs PASS");
    return 0;
}
