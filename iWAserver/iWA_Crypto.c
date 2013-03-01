

#include "iWA.h"



void iWA_Crypto_Sha1ResultBigNumber(SHA1Context *sha_ctx, BIGNUM *result)
{
    iWAuint32 a,b;
    iWAuint8 c;
    iWAuint8 digest[SHA1HashSize];
    
    if(sha_ctx == NULL || result == NULL)    return;

    SHA1Result(sha_ctx, digest);    

    for(a = 0, b = SHA1HashSize - 1; a < SHA1HashSize/2; a++, b--)
    {
        c = digest[a];
        digest[a] = digest[b];
        digest[b] = c;
    }    

    BN_bin2bn(digest, SHA1HashSize, result);   
}

void iWA_Crypto_Sha1Interleave(SHA1Context *sha_ctx, BIGNUM *result, BIGNUM *input)
{
#define iWAmacro_CRYPTO_SHA1_INTERLEAVE_INPUT_SIZE        (32)
#define iWAmacro_CRYPTO_SHA1_INTERLEAVE_RESULT_SIZE      (40)

    iWAuint8 t[iWAmacro_CRYPTO_SHA1_INTERLEAVE_INPUT_SIZE];
    iWAuint8 t1[iWAmacro_CRYPTO_SHA1_INTERLEAVE_INPUT_SIZE/2];
    iWAuint8 digest[SHA1HashSize];
    iWAuint8 vK[iWAmacro_CRYPTO_SHA1_INTERLEAVE_RESULT_SIZE];
    iWAint32 i, j;

    BN_bn2bin(input, t);
    
    for(i = 0, j = sizeof(t1) - 1; j >= 0; i++, j--)    t1[j] = t[i * 2];
    SHA1Reset(sha_ctx);    
    SHA1Input(sha_ctx, t1, sizeof(t1));
    SHA1Result(sha_ctx, digest);    
    for(i = 0, j = SHA1HashSize - 1; j >= 0; i++, j--)   vK[i*2] = digest[j];
    
    for(i = 0, j = sizeof(t1) - 1; j >= 0; i++, j--)    t1[j] = t[i * 2 + 1];
    SHA1Reset(sha_ctx);    
    SHA1Input(sha_ctx, t1, sizeof(t1));
    SHA1Result(sha_ctx, digest);    
    for(i = 0, j = SHA1HashSize - 1; j >= 0; i++, j--)   vK[i*2 + 1] = digest[j];

    BN_bin2bn(vK, iWAmacro_CRYPTO_SHA1_INTERLEAVE_RESULT_SIZE, result);   
}

void iWA_Crypto_Sha1InputUint32(SHA1Context *sha_ctx, iWAuint32 i)
{
    iWAuint8 bin[4];

    if(sha_ctx == NULL) return;

    bin[0] = (iWAuint8)i;
    bin[1] = (iWAuint8)(i >> 8);
    bin[2] = (iWAuint8)(i >> 16);
    bin[3] = (iWAuint8)(i >> 24);

    SHA1Input(sha_ctx, bin, 4);
}


void iWA_Crypto_Sha1InputBigNumber(SHA1Context *sha_ctx, BIGNUM *bn)
{
#define iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE        (128)

    iWAuint8 bn_bin[iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE];   /* support maxium 1024 bits BN */
    iWAuint32 bn_size;
    iWAuint32 a,b;
    iWAuint8 c;

    if(sha_ctx == NULL || bn == NULL)    return;
    
    if(BN_num_bytes(bn) > iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE)  return;    /* BN to long */

    bn_size = BN_bn2bin(bn, bn_bin);
    
    for(a=0,b=bn_size-1; a<bn_size/2; a++,b--)  /* reverse bn_bin */
    {
        c = bn_bin[a];
        bn_bin[a] = bn_bin[b];
        bn_bin[b] = c;
    }   
    
    SHA1Input(sha_ctx, bn_bin, bn_size);
}



void iWA_Crypto_Sha1HashBigNumbers(SHA1Context *sha_ctx, BIGNUM *result, BIGNUM *bn0, ...)
{
#define iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE        (128)

    va_list v;
    BIGNUM *bn;
    iWAuint8 bn_bin[iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE];   /* support maxium 1024 bits BN */
    iWAuint32 bn_size;
    iWAuint32 a,b;
    iWAuint8 c;

    if(sha_ctx == NULL || result == NULL || bn0 == NULL)    return;

    SHA1Reset(sha_ctx);
    
    va_start(v, bn0);
    bn = bn0;
    while (bn)
    {
        iWA_Crypto_Sha1InputBigNumber(sha_ctx, bn);

    #if 0
        if(BN_num_bytes(bn) > iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE)  return;    /* BN to long */
    
        bn_size = BN_bn2bin(bn, bn_bin);
        
        for(a=0,b=bn_size-1; a<bn_size/2; a++,b--)  /* reverse bn_bin */
        {
            c = bn_bin[a];
            bn_bin[a] = bn_bin[b];
            bn_bin[b] = c;
        }   
        
        SHA1Input(sha_ctx, bn_bin, bn_size);
    #endif
        
        bn = va_arg(v, BIGNUM*);
    }
    va_end(v);

    iWA_Crypto_Sha1ResultBigNumber(sha_ctx, result);
}




#if 0
void iWA_Crypto_Sha1InputBigNumbers(SHA1Context *sha_ctx, BIGNUM *bn0, ...)
{
#define iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE        (128)

    va_list v;
    BIGNUM *bn;
    iWAuint8 bn_bin[iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE];   /* support maxium 1024 bits BN */
    iWAuint32 bn_size;
    iWAuint32 a,b;
    iWAuint8 c;

    if(sha_ctx == NULL || bn0 == NULL)    return;
    
    va_start(v, bn0);
    bn = bn0;
    while (bn)
    {
        if(BN_num_bytes(bn) > iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE)  return;    /* BN to long */
    
        bn_size = BN_bn2bin(bn, bn_bin);
        
        for(a=0,b=bn_size-1; a<bn_size/2; a++,b--)  /* reverse bn_bin */
        {
            c = bn_bin[a];
            bn_bin[a] = bn_bin[b];
            bn_bin[b] = c;
        }   
        
        SHA1Input(sha_ctx, bn_bin, bn_size);
        bn = va_arg(v, BIGNUM*);
    }
    va_end(v);
}


void iWA_Crypto_Sha1HashBigNumbers(SHA1Context *sha_ctx, BIGNUM *result, BIGNUM *bn0, ...)
{
#define iWAmacro_CRYPTO_SHA1_INPUT_BIGNUMBERS_SIZE        (128)

    va_list v;
    BIGNUM *bn;

    if(sha_ctx == NULL || result == NULL || bn0 == NULL)    return;

    SHA1Reset(sha_ctx);
    
    va_start(v, bn0);
    iWA_Crypto_Sha1InputBigNumbers(sha_ctx, bn0, v);
    va_end(v);

    iWA_Crypto_Sha1ResultBigNumber(sha_ctx, result);
}

#endif


#if 0
void iWA_Crypto_TestSHA1(void)
{
    iWAuint8 s[32] = 
    {
        0x98, 0x79, 0x0A, 0x0C, 0x01, 0x51, 0xE9, 0xD7, 
        0xBD, 0x04, 0xC4, 0x3B, 0xC8, 0xBD, 0xC0, 0xD4, 
        0xD7, 0x06, 0x76, 0x12, 0x9C, 0x0B, 0x56, 0x56, 
        0x21, 0xEA, 0x40, 0x7D, 0x10, 0xFF, 0xE7, 0xA5
    };

    iWAuint8 p[20] = 
    {
        0x0C, 0x4B, 0x05, 0xE6, 0x9D, 0x9A, 0x17, 0xDD, 
        0x38, 0xB5, 0x2A, 0x94, 0x42, 0xD7, 0x69, 0xE8, 
        0x5C, 0xB2, 0x32, 0xCA
    };


    iWAint32 ret;

    static SHA1Context ctx;
    static iWAuint8 digest[SHA1HashSize];

    ret = SHA1Reset(&ctx);
    ret = SHA1Input(&ctx, "LOUHAO:LOUHAO", 13);
    ret = SHA1Result(&ctx, digest); // digest should be CA32B25CE869D742942AB538DD179A9DE6054B0C

    {
        int a,b;
        iWAuint8 c;
        for(a=0,b=31;a<16;a++,b--)
        {
            c = s[a];
            s[a] = s[b];
            s[b] = c;
        }
        for(a=0,b=19;a<10;a++,b--)
        {
            c = p[a];
            p[a] = p[b];
            p[b] = c;
        }

    }

    ret = SHA1Reset(&ctx);
    ret = SHA1Input(&ctx, s, 32);
    ret = SHA1Input(&ctx, p, 20);
    ret = SHA1Result(&ctx, digest);  //digest should be 45DC3D9EDAD2D18DDBDC97ED7FAD827CEC84725E
    
    return;
}

#endif




