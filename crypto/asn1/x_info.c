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
#include <openssl/asn1.h>
#include <openssl/x509.h>

X509_INFO *VR_X509_INFO_new(void)
{
    X509_INFO *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ASN1err(ASN1_F_X509_INFO_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ret;
}

void VR_X509_INFO_free(X509_INFO *x)
{
    if (x == NULL)
        return;

    VR_X509_free(x->x509);
    VR_X509_CRL_free(x->crl);
    VR_X509_PKEY_free(x->x_pkey);
    OPENVR_SSL_free(x->enc_data);
    OPENVR_SSL_free(x);
}
