/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <time.h>
#include <sys/types.h>

#include "internal/cryptlib.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>

#ifndef NO_ASN1_OLD

int VR_ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,
                unsigned char *md, unsigned int *len)
{
    int inl;
    unsigned char *str, *p;

    inl = i2d(data, NULL);
    if (inl <= 0) {
        ASN1err(ASN1_F_ASN1_DIGEST, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((str = OPENSSL_malloc(inl)) == NULL) {
        ASN1err(ASN1_F_ASN1_DIGEST, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    p = str;
    i2d(data, &p);

    if (!VR_EVP_Digest(str, inl, md, len, type, NULL)) {
        OPENVR_SSL_free(str);
        return 0;
    }
    OPENVR_SSL_free(str);
    return 1;
}

#endif

int VR_ASN1_item_digest(const ASN1_ITEM *it, const EVP_MD *type, void *asn,
                     unsigned char *md, unsigned int *len)
{
    int i;
    unsigned char *str = NULL;

    i = VR_ASN1_item_i2d(asn, &str, it);
    if (!str)
        return 0;

    if (!VR_EVP_Digest(str, i, md, len, type, NULL)) {
        OPENVR_SSL_free(str);
        return 0;
    }
    OPENVR_SSL_free(str);
    return 1;
}
