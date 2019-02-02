/*
 * Copyright 2008-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/rand.h>
#include "cms_lcl.h"

/* CMS EncryptedData Utilities */

/* Return BIO based on EncryptedContentInfo and key */

BIO *VR_cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec)
{
    BIO *b;
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *ciph;
    X509_ALGOR *calg = ec->contentEncryptionAlgorithm;
    unsigned char iv[EVP_MAX_IV_LENGTH], *piv = NULL;
    unsigned char *tkey = NULL;
    size_t tkeylen = 0;

    int ok = 0;

    int enc, keep_key = 0;

    enc = ec->cipher ? 1 : 0;

    b = VR_BIO_new(VR_BIO_f_cipher());
    if (b == NULL) {
        CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    BIO_get_cipher_ctx(b, &ctx);

    if (enc) {
        ciph = ec->cipher;
        /*
         * If not keeping key set cipher to NULL so subsequent calls decrypt.
         */
        if (ec->key)
            ec->cipher = NULL;
    } else {
        ciph = EVP_get_cipherbyobj(calg->algorithm);

        if (!ciph) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO, CMS_R_UNKNOWN_CIPHER);
            goto err;
        }
    }

    if (VR_EVP_CipherInit_ex(ctx, ciph, NULL, NULL, NULL, enc) <= 0) {
        CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
               CMS_R_CIPHER_INITIALISATION_ERROR);
        goto err;
    }

    if (enc) {
        int ivlen;
        calg->algorithm = VR_OBJ_nid2obj(EVP_CIPHER_CTX_type(ctx));
        /* Generate a random IV if we need one */
        ivlen = VR_EVP_CIPHER_CTX_iv_length(ctx);
        if (ivlen > 0) {
            if (VR_RAND_bytes(iv, ivlen) <= 0)
                goto err;
            piv = iv;
        }
    } else if (VR_EVP_CIPHER_asn1_to_param(ctx, calg->parameter) <= 0) {
        CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
               CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
        goto err;
    }
    tkeylen = VR_EVP_CIPHER_CTX_key_length(ctx);
    /* Generate random session key */
    if (!enc || !ec->key) {
        tkey = OPENSSL_malloc(tkeylen);
        if (tkey == NULL) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (VR_EVP_CIPHER_CTX_rand_key(ctx, tkey) <= 0)
            goto err;
    }

    if (!ec->key) {
        ec->key = tkey;
        ec->keylen = tkeylen;
        tkey = NULL;
        if (enc)
            keep_key = 1;
        else
            VR_ERR_clear_error();

    }

    if (ec->keylen != tkeylen) {
        /* If necessary set key length */
        if (VR_EVP_CIPHER_CTX_set_key_length(ctx, ec->keylen) <= 0) {
            /*
             * Only reveal failure if debugging so we don't leak information
             * which may be useful in MMA.
             */
            if (enc || ec->debug) {
                CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
                       CMS_R_INVALID_KEY_LENGTH);
                goto err;
            } else {
                /* Use random key */
                OPENVR_SSL_clear_free(ec->key, ec->keylen);
                ec->key = tkey;
                ec->keylen = tkeylen;
                tkey = NULL;
                VR_ERR_clear_error();
            }
        }
    }

    if (VR_EVP_CipherInit_ex(ctx, NULL, NULL, ec->key, piv, enc) <= 0) {
        CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
               CMS_R_CIPHER_INITIALISATION_ERROR);
        goto err;
    }
    if (enc) {
        calg->parameter = VR_ASN1_TYPE_new();
        if (calg->parameter == NULL) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (VR_EVP_CIPHER_param_to_asn1(ctx, calg->parameter) <= 0) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO,
                   CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
            goto err;
        }
        /* If parameter type not set omit parameter */
        if (calg->parameter->type == V_ASN1_UNDEF) {
            VR_ASN1_TYPE_free(calg->parameter);
            calg->parameter = NULL;
        }
    }
    ok = 1;

 err:
    if (!keep_key || !ok) {
        OPENVR_SSL_clear_free(ec->key, ec->keylen);
        ec->key = NULL;
    }
    OPENVR_SSL_clear_free(tkey, tkeylen);
    if (ok)
        return b;
    VR_BIO_free(b);
    return NULL;
}

int VR_cms_EncryptedContent_init(CMS_EncryptedContentInfo *ec,
                              const EVP_CIPHER *cipher,
                              const unsigned char *key, size_t keylen)
{
    ec->cipher = cipher;
    if (key) {
        if ((ec->key = OPENSSL_malloc(keylen)) == NULL) {
            CMSerr(CMS_F_CMS_ENCRYPTEDCONTENT_INIT, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(ec->key, key, keylen);
    }
    ec->keylen = keylen;
    if (cipher)
        ec->contentType = VR_OBJ_nid2obj(NID_pkcs7_data);
    return 1;
}

int VR_CMS_EncryptedData_set1_key(CMS_ContentInfo *cms, const EVP_CIPHER *ciph,
                               const unsigned char *key, size_t keylen)
{
    CMS_EncryptedContentInfo *ec;
    if (!key || !keylen) {
        CMSerr(CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY, CMS_R_NO_KEY);
        return 0;
    }
    if (ciph) {
        cms->d.encryptedData = M_ASN1_new_of(CMS_EncryptedData);
        if (!cms->d.encryptedData) {
            CMSerr(CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        cms->contentType = VR_OBJ_nid2obj(NID_pkcs7_encrypted);
        cms->d.encryptedData->version = 0;
    } else if (VR_OBJ_obj2nid(cms->contentType) != NID_pkcs7_encrypted) {
        CMSerr(CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY, CMS_R_NOT_ENCRYPTED_DATA);
        return 0;
    }
    ec = cms->d.encryptedData->encryptedContentInfo;
    return VR_cms_EncryptedContent_init(ec, ciph, key, keylen);
}

BIO *VR_cms_EncryptedData_init_bio(CMS_ContentInfo *cms)
{
    CMS_EncryptedData *enc = cms->d.encryptedData;
    if (enc->encryptedContentInfo->cipher && enc->unprotectedAttrs)
        enc->version = 2;
    return VR_cms_EncryptedContent_init_bio(enc->encryptedContentInfo);
}
