/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
# include <openssl/x509.h>
# include <openssl/evp.h>
# include <openssl/hmac.h>
# include "evp_locl.h"

/* set this to print out info about the keygen algorithm */
/* #define OPENSSL_DEBUG_PKCS5V2 */

# ifdef OPENSSL_DEBUG_PKCS5V2
static void h__dump(const unsigned char *p, int len);
# endif

/*
 * This is an implementation of PKCS#5 v2.0 password based encryption key
 * derivation function PBKDF2. VR_SHA1 version verified against test vectors
 * posted by Peter Gutmann to the PKCS-TNG mailing list.
 */

int VR_PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
                      const unsigned char *salt, int saltlen, int iter,
                      const EVP_MD *digest, int keylen, unsigned char *out)
{
    const char *empty = "";
    unsigned char digtmp[EVP_MAX_MD_SIZE], *p, itmp[4];
    int cplen, j, k, tkeylen, mdlen;
    unsigned long i = 1;
    VR_HMAC_CTX *hctx_tpl = NULL, *hctx = NULL;

    mdlen = VR_EVP_MD_size(digest);
    if (mdlen < 0)
        return 0;

    hctx_tpl = VR_HMAC_CTX_new();
    if (hctx_tpl == NULL)
        return 0;
    p = out;
    tkeylen = keylen;
    if (pass == NULL) {
        pass = empty;
        passlen = 0;
    } else if (passlen == -1) {
        passlen = strlen(pass);
    }
    if (!VR_HMAC_Init_ex(hctx_tpl, pass, passlen, digest, NULL)) {
        VR_HMAC_CTX_free(hctx_tpl);
        return 0;
    }
    hctx = VR_HMAC_CTX_new();
    if (hctx == NULL) {
        VR_HMAC_CTX_free(hctx_tpl);
        return 0;
    }
    while (tkeylen) {
        if (tkeylen > mdlen)
            cplen = mdlen;
        else
            cplen = tkeylen;
        /*
         * We are unlikely to ever use more than 256 blocks (5120 bits!) but
         * just in case...
         */
        itmp[0] = (unsigned char)((i >> 24) & 0xff);
        itmp[1] = (unsigned char)((i >> 16) & 0xff);
        itmp[2] = (unsigned char)((i >> 8) & 0xff);
        itmp[3] = (unsigned char)(i & 0xff);
        if (!VR_HMAC_CTX_copy(hctx, hctx_tpl)) {
            VR_HMAC_CTX_free(hctx);
            VR_HMAC_CTX_free(hctx_tpl);
            return 0;
        }
        if (!VR_HMAC_Update(hctx, salt, saltlen)
            || !VR_HMAC_Update(hctx, itmp, 4)
            || !VR_HMAC_Final(hctx, digtmp, NULL)) {
            VR_HMAC_CTX_free(hctx);
            VR_HMAC_CTX_free(hctx_tpl);
            return 0;
        }
        memcpy(p, digtmp, cplen);
        for (j = 1; j < iter; j++) {
            if (!VR_HMAC_CTX_copy(hctx, hctx_tpl)) {
                VR_HMAC_CTX_free(hctx);
                VR_HMAC_CTX_free(hctx_tpl);
                return 0;
            }
            if (!VR_HMAC_Update(hctx, digtmp, mdlen)
                || !VR_HMAC_Final(hctx, digtmp, NULL)) {
                VR_HMAC_CTX_free(hctx);
                VR_HMAC_CTX_free(hctx_tpl);
                return 0;
            }
            for (k = 0; k < cplen; k++)
                p[k] ^= digtmp[k];
        }
        tkeylen -= cplen;
        i++;
        p += cplen;
    }
    VR_HMAC_CTX_free(hctx);
    VR_HMAC_CTX_free(hctx_tpl);
# ifdef OPENSSL_DEBUG_PKCS5V2
    fprintf(stderr, "Password:\n");
    h__dump(pass, passlen);
    fprintf(stderr, "Salt:\n");
    h__dump(salt, saltlen);
    fprintf(stderr, "Iteration count %d\n", iter);
    fprintf(stderr, "Key:\n");
    h__dump(out, keylen);
# endif
    return 1;
}

int VR_PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,
                           const unsigned char *salt, int saltlen, int iter,
                           int keylen, unsigned char *out)
{
    return VR_PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, VR_EVP_sha1(),
                             keylen, out);
}

/*
 * Now the key derivation function itself. This is a bit evil because it has
 * to check the ASN1 parameters are valid: and there are quite a few of
 * them...
 */

int VR_PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                          ASN1_TYPE *param, const EVP_CIPHER *c,
                          const EVP_MD *md, int en_de)
{
    PBE2PARAM *pbe2 = NULL;
    const EVP_CIPHER *cipher;
    EVP_PBE_KEYGEN *kdf;

    int rv = 0;

    pbe2 = VR_ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBE2PARAM), param);
    if (pbe2 == NULL) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN, EVP_R_DECODE_ERROR);
        goto err;
    }

    /* See if we recognise the key derivation function */
    if (!VR_EVP_PBE_find(EVP_PBE_TYPE_KDF, VR_OBJ_obj2nid(pbe2->keyfunc->algorithm),
                        NULL, NULL, &kdf)) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN,
               EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
        goto err;
    }

    /*
     * lets see if we recognise the encryption algorithm.
     */

    cipher = EVP_get_cipherbyobj(pbe2->encryption->algorithm);

    if (!cipher) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN, EVP_R_UNSUPPORTED_CIPHER);
        goto err;
    }

    /* Fixup cipher based on AlgorithmIdentifier */
    if (!VR_EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, en_de))
        goto err;
    if (VR_EVP_CIPHER_asn1_to_param(ctx, pbe2->encryption->parameter) < 0) {
        EVPerr(EVP_F_PKCS5_V2_PBE_KEYIVGEN, EVP_R_CIPHER_PARAMETER_ERROR);
        goto err;
    }
    rv = kdf(ctx, pass, passlen, pbe2->keyfunc->parameter, NULL, NULL, en_de);
 err:
    VR_PBE2PARAM_free(pbe2);
    return rv;
}

int VR_PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
                             int passlen, ASN1_TYPE *param,
                             const EVP_CIPHER *c, const EVP_MD *md, int en_de)
{
    unsigned char *salt, key[EVP_MAX_KEY_LENGTH];
    int saltlen, iter;
    int rv = 0;
    unsigned int keylen = 0;
    int prf_nid, hmac_md_nid;
    PBKDF2PARAM *kdf = NULL;
    const EVP_MD *prfmd;

    if (VR_EVP_CIPHER_CTX_cipher(ctx) == NULL) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_NO_CIPHER_SET);
        goto err;
    }
    keylen = VR_EVP_CIPHER_CTX_key_length(ctx);
    OPENSSL_assert(keylen <= sizeof(key));

    /* Decode parameter */

    kdf = VR_ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBKDF2PARAM), param);

    if (kdf == NULL) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_DECODE_ERROR);
        goto err;
    }

    keylen = VR_EVP_CIPHER_CTX_key_length(ctx);

    /* Now check the parameters of the kdf */

    if (kdf->keylength && (VR_ASN1_INTEGER_get(kdf->keylength) != (int)keylen)) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_UNSUPPORTED_KEYLENGTH);
        goto err;
    }

    if (kdf->prf)
        prf_nid = VR_OBJ_obj2nid(kdf->prf->algorithm);
    else
        prf_nid = NID_hmacWithVR_SHA1;

    if (!VR_EVP_PBE_find(EVP_PBE_TYPE_PRF, prf_nid, NULL, &hmac_md_nid, 0)) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    prfmd = EVP_get_digestbynid(hmac_md_nid);
    if (prfmd == NULL) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_UNSUPPORTED_PRF);
        goto err;
    }

    if (kdf->salt->type != V_ASN1_OCTET_STRING) {
        EVPerr(EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN, EVP_R_UNSUPPORTED_SALT_TYPE);
        goto err;
    }

    /* it seems that its all OK */
    salt = kdf->salt->value.octet_string->data;
    saltlen = kdf->salt->value.octet_string->length;
    iter = VR_ASN1_INTEGER_get(kdf->iter);
    if (!VR_PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, prfmd,
                           keylen, key))
        goto err;
    rv = VR_EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, en_de);
 err:
    VR_OPENSSL_cleanse(key, keylen);
    VR_PBKDF2PARAM_free(kdf);
    return rv;
}

# ifdef OPENSSL_DEBUG_PKCS5V2
static void h__dump(const unsigned char *p, int len)
{
    for (; len--; p++)
        fprintf(stderr, "%02X ", *p);
    fprintf(stderr, "\n");
}
# endif
