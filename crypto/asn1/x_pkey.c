/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

X509_PKEY *VR_X509_PKEY_new(void)
{
    X509_PKEY *ret = NULL;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        goto err;

    ret->enc_algor = VR_X509_ALGOR_new();
    ret->enc_pkey = VR_ASN1_OCTET_STRING_new();
    if (ret->enc_algor == NULL || ret->enc_pkey == NULL)
        goto err;

    return ret;
err:
    VR_X509_PKEY_free(ret);
    ASN1err(ASN1_F_X509_PKEY_NEW, ERR_R_MALLOC_FAILURE);
    return NULL;
}

void VR_X509_PKEY_free(X509_PKEY *x)
{
    if (x == NULL)
        return;

    VR_X509_ALGOR_free(x->enc_algor);
    VR_ASN1_OCTET_STRING_free(x->enc_pkey);
    VR_EVP_PKEY_free(x->dec_pkey);
    if (x->key_free)
        VR_OPENSSL_free(x->key_data);
    VR_OPENSSL_free(x);
}
