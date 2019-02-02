/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/dh.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"

int VR_pem_check_suffix(const char *pem_str, const char *suffix);

EVP_PKEY *VR_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    int slen;
    EVP_PKEY *ret = NULL;

    if (!VR_PEM_bytes_read_bio_secmem(&data, &len, &nm, PEM_STRING_EVP_PKEY, bp,
                                   cb, u))
        return NULL;
    p = data;

    if (strcmp(nm, PEM_STRING_PKCS8INF) == 0) {
        PKCS8_PRIV_KEY_INFO *p8inf;
        p8inf = VR_d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
        if (!p8inf)
            goto p8err;
        ret = VR_EVP_PKCS82PKEY(p8inf);
        if (x) {
            VR_EVP_PKEY_free((EVP_PKEY *)*x);
            *x = ret;
        }
        VR_PKCS8_PRIV_KEY_INFO_free(p8inf);
    } else if (strcmp(nm, PEM_STRING_PKCS8) == 0) {
        PKCS8_PRIV_KEY_INFO *p8inf;
        X509_SIG *p8;
        int klen;
        char psbuf[PEM_BUFSIZE];
        p8 = VR_d2i_X509_SIG(NULL, &p, len);
        if (!p8)
            goto p8err;
        if (cb)
            klen = cb(psbuf, PEM_BUFSIZE, 0, u);
        else
            klen = VR_PEM_def_callback(psbuf, PEM_BUFSIZE, 0, u);
        if (klen < 0) {
            PEMerr(PEM_F_PEM_READ_BIO_PRIVATEKEY, PEM_R_BAD_PASSWORD_READ);
            VR_X509_SIG_free(p8);
            goto err;
        }
        p8inf = VR_PKCS8_decrypt(p8, psbuf, klen);
        VR_X509_SIG_free(p8);
        VR_OPENSSL_cleanse(psbuf, klen);
        if (!p8inf)
            goto p8err;
        ret = VR_EVP_PKCS82PKEY(p8inf);
        if (x) {
            VR_EVP_PKEY_free((EVP_PKEY *)*x);
            *x = ret;
        }
        VR_PKCS8_PRIV_KEY_INFO_free(p8inf);
    } else if ((slen = VR_pem_check_suffix(nm, "PRIVATE KEY")) > 0) {
        const EVP_PKEY_ASN1_METHOD *ameth;
        ameth = VR_EVP_PKEY_asn1_find_str(NULL, nm, slen);
        if (!ameth || !ameth->old_priv_decode)
            goto p8err;
        ret = VR_d2i_PrivateKey(ameth->pkey_id, x, &p, len);
    }
 p8err:
    if (ret == NULL)
        PEMerr(PEM_F_PEM_READ_BIO_PRIVATEKEY, ERR_R_ASN1_LIB);
 err:
    OPENSSL_secure_free(nm);
    OPENSSL_secure_clear_free(data, len);
    return ret;
}

int VR_PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                             unsigned char *kstr, int klen,
                             pem_password_cb *cb, void *u)
{
    if (x->ameth == NULL || x->ameth->priv_encode != NULL)
        return VR_PEM_write_bio_PKCS8PrivateKey(bp, x, enc,
                                             (char *)kstr, klen, cb, u);
    return VR_PEM_write_bio_PrivateKey_traditional(bp, x, enc, kstr, klen, cb, u);
}

int VR_PEM_write_bio_PrivateKey_traditional(BIO *bp, EVP_PKEY *x,
                                         const EVP_CIPHER *enc,
                                         unsigned char *kstr, int klen,
                                         pem_password_cb *cb, void *u)
{
    char pem_str[80];
    VR_BIO_snprintf(pem_str, 80, "%s PRIVATE KEY", x->ameth->pem_str);
    return VR_PEM_ASN1_write_bio((i2d_of_void *)VR_i2d_PrivateKey,
                              pem_str, bp, x, enc, kstr, klen, cb, u);
}

EVP_PKEY *VR_PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    int slen;
    EVP_PKEY *ret = NULL;

    if (!VR_PEM_bytes_read_bio(&data, &len, &nm, PEM_STRING_PARAMETERS,
                            bp, 0, NULL))
        return NULL;
    p = data;

    if ((slen = VR_pem_check_suffix(nm, "PARAMETERS")) > 0) {
        ret = VR_EVP_PKEY_new();
        if (ret == NULL)
            goto err;
        if (!VR_EVP_PKEY_set_type_str(ret, nm, slen)
            || !ret->ameth->param_decode
            || !ret->ameth->param_decode(ret, &p, len)) {
            VR_EVP_PKEY_free(ret);
            ret = NULL;
            goto err;
        }
        if (x) {
            VR_EVP_PKEY_free((EVP_PKEY *)*x);
            *x = ret;
        }
    }
 err:
    if (ret == NULL)
        PEMerr(PEM_F_PEM_READ_BIO_PARAMETERS, ERR_R_ASN1_LIB);
    OPENVR_SSL_free(nm);
    OPENVR_SSL_free(data);
    return ret;
}

int VR_PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x)
{
    char pem_str[80];
    if (!x->ameth || !x->ameth->param_encode)
        return 0;

    VR_BIO_snprintf(pem_str, 80, "%s PARAMETERS", x->ameth->pem_str);
    return VR_PEM_ASN1_write_bio((i2d_of_void *)x->ameth->param_encode,
                              pem_str, bp, x, NULL, NULL, 0, 0, NULL);
}

#ifndef OPENSSL_NO_STDIO
EVP_PKEY *VR_PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                              void *u)
{
    BIO *b;
    EVP_PKEY *ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_PRIVATEKEY, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_PEM_read_bio_PrivateKey(b, x, cb, u);
    VR_BIO_free(b);
    return ret;
}

int VR_PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                         unsigned char *kstr, int klen,
                         pem_password_cb *cb, void *u)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
        PEMerr(PEM_F_PEM_WRITE_PRIVATEKEY, ERR_R_BUF_LIB);
        return 0;
    }
    ret = VR_PEM_write_bio_PrivateKey(b, x, enc, kstr, klen, cb, u);
    VR_BIO_free(b);
    return ret;
}

#endif

#ifndef OPENSSL_NO_DH

/* Transparently read in PKCS#3 or X9.42 DH parameters */

DH *VR_PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u)
{
    char *nm = NULL;
    const unsigned char *p = NULL;
    unsigned char *data = NULL;
    long len;
    DH *ret = NULL;

    if (!VR_PEM_bytes_read_bio(&data, &len, &nm, PEM_STRING_DHPARAMS, bp, cb, u))
        return NULL;
    p = data;

    if (strcmp(nm, PEM_STRING_DHXPARAMS) == 0)
        ret = VR_d2i_DHxparams(x, &p, len);
    else
        ret = VR_d2i_DHparams(x, &p, len);

    if (ret == NULL)
        PEMerr(PEM_F_PEM_READ_BIO_DHPARAMS, ERR_R_ASN1_LIB);
    OPENVR_SSL_free(nm);
    OPENVR_SSL_free(data);
    return ret;
}

# ifndef OPENSSL_NO_STDIO
DH *VR_PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u)
{
    BIO *b;
    DH *ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_DHPARAMS, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_PEM_read_bio_DHparams(b, x, cb, u);
    VR_BIO_free(b);
    return ret;
}
# endif

#endif
