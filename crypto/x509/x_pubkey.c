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
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "internal/x509_int.h"
#include <openssl/rsa.h>
#include <openssl/dsa.h>

struct X509_pubkey_st {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;
    EVP_PKEY *pkey;
};

static int VR_x509_pubkey_decode(EVP_PKEY **pk, X509_PUBKEY *key);

/* Minor tweak to operation: free up EVP_PKEY */
static int VR_pubkey_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                     void *exarg)
{
    if (operation == ASN1_OP_FREE_POST) {
        X509_PUBKEY *pubkey = (X509_PUBKEY *)*pval;
        VR_EVP_PKEY_free(pubkey->pkey);
    } else if (operation == ASN1_OP_D2I_POST) {
        /* Attempt to decode public key and cache in pubkey structure. */
        X509_PUBKEY *pubkey = (X509_PUBKEY *)*pval;
        VR_EVP_PKEY_free(pubkey->pkey);
        pubkey->pkey = NULL;
        /*
         * Opportunistically decode the key but remove any non fatal errors
         * from the queue. Subsequent explicit attempts to decode/use the key
         * will return an appropriate error.
         */
        VR_ERR_set_mark();
        if (VR_x509_pubkey_decode(&pubkey->pkey, pubkey) == -1)
            return 0;
        VR_ERR_pop_to_mark();
    }
    return 1;
}

ASN1_SEQUENCE_cb(X509_PUBKEY, VR_pubkey_cb) = {
        ASN1_SIMPLE(X509_PUBKEY, algor, X509_ALGOR),
        ASN1_SIMPLE(X509_PUBKEY, public_key, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END_cb(X509_PUBKEY, X509_PUBKEY)

IMPLEMENT_ASN1_FUNCTIONS(X509_PUBKEY)

int VR_X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey)
{
    X509_PUBKEY *pk = NULL;

    if (x == NULL)
        return 0;

    if ((pk = VR_X509_PUBKEY_new()) == NULL)
        goto error;

    if (pkey->ameth) {
        if (pkey->ameth->pub_encode) {
            if (!pkey->ameth->pub_encode(pk, pkey)) {
                X509err(X509_F_X509_PUBKEY_SET,
                        X509_R_PUBLIC_KEY_ENCODE_ERROR);
                goto error;
            }
        } else {
            X509err(X509_F_X509_PUBKEY_SET, X509_R_METHOD_NOT_SUPPORTED);
            goto error;
        }
    } else {
        X509err(X509_F_X509_PUBKEY_SET, X509_R_UNSUPPORTED_ALGORITHM);
        goto error;
    }

    VR_X509_PUBKEY_free(*x);
    *x = pk;
    pk->pkey = pkey;
    VR_EVP_PKEY_up_ref(pkey);
    return 1;

 error:
    VR_X509_PUBKEY_free(pk);
    return 0;
}

/*
 * Attempt to decode a public key.
 * Returns 1 on success, 0 for a decode failure and -1 for a fatal
 * error e.g. malloc failure.
 */


static int VR_x509_pubkey_decode(EVP_PKEY **ppkey, X509_PUBKEY *key)
{
    EVP_PKEY *pkey = VR_EVP_PKEY_new();

    if (pkey == NULL) {
        X509err(X509_F_X509_PUBKEY_DECODE, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    if (!VR_EVP_PKEY_set_type(pkey, VR_OBJ_obj2nid(key->algor->algorithm))) {
        X509err(X509_F_X509_PUBKEY_DECODE, X509_R_UNSUPPORTED_ALGORITHM);
        goto error;
    }

    if (pkey->ameth->pub_decode) {
        /*
         * Treat any failure of pub_decode as a decode error. In
         * future we could have different return codes for decode
         * errors and fatal errors such as malloc failure.
         */
        if (!pkey->ameth->pub_decode(pkey, key)) {
            X509err(X509_F_X509_PUBKEY_DECODE, X509_R_PUBLIC_KEY_DECODE_ERROR);
            goto error;
        }
    } else {
        X509err(X509_F_X509_PUBKEY_DECODE, X509_R_METHOD_NOT_SUPPORTED);
        goto error;
    }

    *ppkey = pkey;
    return 1;

 error:
    VR_EVP_PKEY_free(pkey);
    return 0;
}

EVP_PKEY *VR_X509_PUBKEY_get0(X509_PUBKEY *key)
{
    EVP_PKEY *ret = NULL;

    if (key == NULL || key->public_key == NULL)
        return NULL;

    if (key->pkey != NULL)
        return key->pkey;

    /*
     * When the key ASN.1 is initially parsed an attempt is made to
     * decode the public key and cache the EVP_PKEY structure. If this
     * operation fails the cached value will be NULL. Parsing continues
     * to allow parsing of unknown key types or unsupported forms.
     * We repeat the decode operation so the appropriate errors are left
     * in the queue.
     */
    VR_x509_pubkey_decode(&ret, key);
    /* If decode doesn't fail something bad happened */
    if (ret != NULL) {
        X509err(X509_F_X509_PUBKEY_GET0, ERR_R_INTERNAL_ERROR);
        VR_EVP_PKEY_free(ret);
    }

    return NULL;
}

EVP_PKEY *VR_X509_PUBKEY_get(X509_PUBKEY *key)
{
    EVP_PKEY *ret = VR_X509_PUBKEY_get0(key);
    if (ret != NULL)
        VR_EVP_PKEY_up_ref(ret);
    return ret;
}

/*
 * Now two pseudo ASN1 routines that take an EVP_PKEY structure and encode or
 * decode as X509_PUBKEY
 */

EVP_PKEY *VR_d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length)
{
    X509_PUBKEY *xpk;
    EVP_PKEY *pktmp;
    const unsigned char *q;
    q = *pp;
    xpk = VR_d2i_X509_PUBKEY(NULL, &q, length);
    if (!xpk)
        return NULL;
    pktmp = VR_X509_PUBKEY_get(xpk);
    VR_X509_PUBKEY_free(xpk);
    if (!pktmp)
        return NULL;
    *pp = q;
    if (a) {
        VR_EVP_PKEY_free(*a);
        *a = pktmp;
    }
    return pktmp;
}

int VR_i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp)
{
    X509_PUBKEY *xpk = NULL;
    int ret;
    if (!a)
        return 0;
    if (!VR_X509_PUBKEY_set(&xpk, a))
        return -1;
    ret = VR_i2d_X509_PUBKEY(xpk, pp);
    VR_X509_PUBKEY_free(xpk);
    return ret;
}

/*
 * The following are equivalents but which return RSA and DSA keys
 */
#ifndef OPENSSL_NO_RSA
RSA *VR_d2i_RSA_PUBKEY(RSA **a, const unsigned char **pp, long length)
{
    EVP_PKEY *pkey;
    RSA *key;
    const unsigned char *q;
    q = *pp;
    pkey = VR_d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = VR_EVP_PKEY_get1_RSA(pkey);
    VR_EVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        VR_RSA_free(*a);
        *a = key;
    }
    return key;
}

int VR_i2d_RSA_PUBKEY(RSA *a, unsigned char **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    pktmp = VR_EVP_PKEY_new();
    if (pktmp == NULL) {
        ASN1err(ASN1_F_I2D_RSA_PUBKEY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    VR_EVP_PKEY_set1_RSA(pktmp, a);
    ret = VR_i2d_PUBKEY(pktmp, pp);
    VR_EVP_PKEY_free(pktmp);
    return ret;
}
#endif

#ifndef OPENSSL_NO_DSA
DSA *VR_d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length)
{
    EVP_PKEY *pkey;
    DSA *key;
    const unsigned char *q;
    q = *pp;
    pkey = VR_d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = VR_EVP_PKEY_get1_DSA(pkey);
    VR_EVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        VR_DSA_free(*a);
        *a = key;
    }
    return key;
}

int VR_i2d_DSA_PUBKEY(DSA *a, unsigned char **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    pktmp = VR_EVP_PKEY_new();
    if (pktmp == NULL) {
        ASN1err(ASN1_F_I2D_DSA_PUBKEY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    VR_EVP_PKEY_set1_DSA(pktmp, a);
    ret = VR_i2d_PUBKEY(pktmp, pp);
    VR_EVP_PKEY_free(pktmp);
    return ret;
}
#endif

#ifndef OPENSSL_NO_EC
EC_KEY *VR_d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length)
{
    EVP_PKEY *pkey;
    EC_KEY *key;
    const unsigned char *q;
    q = *pp;
    pkey = VR_d2i_PUBKEY(NULL, &q, length);
    if (!pkey)
        return NULL;
    key = VR_EVP_PKEY_get1_EC_KEY(pkey);
    VR_EVP_PKEY_free(pkey);
    if (!key)
        return NULL;
    *pp = q;
    if (a) {
        VR_EC_KEY_free(*a);
        *a = key;
    }
    return key;
}

int VR_i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp)
{
    EVP_PKEY *pktmp;
    int ret;
    if (!a)
        return 0;
    if ((pktmp = VR_EVP_PKEY_new()) == NULL) {
        ASN1err(ASN1_F_I2D_EC_PUBKEY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    VR_EVP_PKEY_set1_EC_KEY(pktmp, a);
    ret = VR_i2d_PUBKEY(pktmp, pp);
    VR_EVP_PKEY_free(pktmp);
    return ret;
}
#endif

int VR_X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj,
                           int ptype, void *pval,
                           unsigned char *penc, int penclen)
{
    if (!VR_X509_ALGOR_set0(pub->algor, aobj, ptype, pval))
        return 0;
    if (penc) {
        VR_OPENSSL_free(pub->public_key->data);
        pub->public_key->data = penc;
        pub->public_key->length = penclen;
        /* Set number of unused bits to zero */
        pub->public_key->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        pub->public_key->flags |= ASN1_STRING_FLAG_BITS_LEFT;
    }
    return 1;
}

int VR_X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg,
                           const unsigned char **pk, int *ppklen,
                           X509_ALGOR **pa, X509_PUBKEY *pub)
{
    if (ppkalg)
        *ppkalg = pub->algor->algorithm;
    if (pk) {
        *pk = pub->public_key->data;
        *ppklen = pub->public_key->length;
    }
    if (pa)
        *pa = pub->algor;
    return 1;
}

ASN1_BIT_STRING *VR_X509_get0_pubkey_bitstr(const X509 *x)
{
    if (x == NULL)
        return NULL;
    return x->cert_info.key->public_key;
}
