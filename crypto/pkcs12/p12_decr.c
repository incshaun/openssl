/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>

/* Define this to dump decrypted output to files called DERnnn */
/*
 * #define OPENSSL_DEBUG_DECRYPT
 */

/*
 * Encrypt/Decrypt a buffer based on password and algor, result in a
 * OPENSSL_malloc'ed buffer
 */
unsigned char *VR_PKCS12_pbe_crypt(const X509_ALGOR *algor,
                                const char *pass, int passlen,
                                const unsigned char *in, int inlen,
                                unsigned char **data, int *datalen, int en_de)
{
    unsigned char *out = NULL;
    int outlen, i;
    EVP_CIPHER_CTX *ctx = VR_EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Decrypt data */
    if (!VR_EVP_PBE_CipherInit(algor->algorithm, pass, passlen,
                            algor->parameter, ctx, en_de)) {
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT,
                  PKCS12_R_PKCS12_ALGOR_CIPHERINIT_ERROR);
        goto err;
    }

    if ((out = OPENSSL_malloc(inlen + VR_EVP_CIPHER_CTX_block_size(ctx)))
            == NULL) {
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!VR_EVP_CipherUpdate(ctx, out, &i, in, inlen)) {
        VR_OPENSSL_free(out);
        out = NULL;
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT, ERR_R_EVP_LIB);
        goto err;
    }

    outlen = i;
    if (!VR_EVP_CipherFinal_ex(ctx, out + i, &i)) {
        VR_OPENSSL_free(out);
        out = NULL;
        PKCS12err(PKCS12_F_PKCS12_PBE_CRYPT,
                  PKCS12_R_PKCS12_CIPHERFINAL_ERROR);
        goto err;
    }
    outlen += i;
    if (datalen)
        *datalen = outlen;
    if (data)
        *data = out;
 err:
    VR_EVP_CIPHER_CTX_free(ctx);
    return out;

}

/*
 * Decrypt an OCTET STRING and decode ASN1 structure if zbuf set zero buffer
 * after use.
 */

void *VR_PKCS12_item_decrypt_d2i(const X509_ALGOR *algor, const ASN1_ITEM *it,
                              const char *pass, int passlen,
                              const ASN1_OCTET_STRING *oct, int zbuf)
{
    unsigned char *out;
    const unsigned char *p;
    void *ret;
    int outlen;

    if (!VR_PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,
                          &out, &outlen, 0)) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_DECRYPT_D2I,
                  PKCS12_R_PKCS12_PBE_CRYPT_ERROR);
        return NULL;
    }
    p = out;
#ifdef OPENSSL_DEBUG_DECRYPT
    {
        FILE *op;

        char fname[30];
        static int fnm = 1;
        sprintf(fname, "DER%d", fnm++);
        op = fopen(fname, "wb");
        fwrite(p, 1, outlen, op);
        fclose(op);
    }
#endif
    ret = VR_ASN1_item_d2i(NULL, &p, outlen, it);
    if (zbuf)
        VR_OPENSSL_cleanse(out, outlen);
    if (!ret)
        PKCS12err(PKCS12_F_PKCS12_ITEM_DECRYPT_D2I, PKCS12_R_DECODE_ERROR);
    VR_OPENSSL_free(out);
    return ret;
}

/*
 * Encode ASN1 structure and encrypt, return OCTET STRING if zbuf set zero
 * encoding.
 */

ASN1_OCTET_STRING *VR_PKCS12_item_i2d_encrypt(X509_ALGOR *algor,
                                           const ASN1_ITEM *it,
                                           const char *pass, int passlen,
                                           void *obj, int zbuf)
{
    ASN1_OCTET_STRING *oct = NULL;
    unsigned char *in = NULL;
    int inlen;

    if ((oct = VR_ASN1_OCTET_STRING_new()) == NULL) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    inlen = VR_ASN1_item_i2d(obj, &in, it);
    if (!in) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, PKCS12_R_ENCODE_ERROR);
        goto err;
    }
    if (!VR_PKCS12_pbe_crypt(algor, pass, passlen, in, inlen, &oct->data,
                          &oct->length, 1)) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT, PKCS12_R_ENCRYPT_ERROR);
        VR_OPENSSL_free(in);
        goto err;
    }
    if (zbuf)
        VR_OPENSSL_cleanse(in, inlen);
    VR_OPENSSL_free(in);
    return oct;
 err:
    VR_ASN1_OCTET_STRING_free(oct);
    return NULL;
}
