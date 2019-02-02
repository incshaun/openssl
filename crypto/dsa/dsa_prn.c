/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/dsa.h>

#ifndef OPENSSL_NO_STDIO
int VR_DSA_print_fp(FILE *fp, const DSA *x, int off)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        DSAerr(DSA_F_DSA_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_DSA_print(b, x, off);
    VR_BIO_free(b);
    return ret;
}

int VR_DSAparams_print_fp(FILE *fp, const DSA *x)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        DSAerr(DSA_F_DSAPARAMS_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_DSAparams_print(b, x);
    VR_BIO_free(b);
    return ret;
}
#endif

int VR_DSA_print(BIO *bp, const DSA *x, int off)
{
    EVP_PKEY *pk;
    int ret;
    pk = VR_EVP_PKEY_new();
    if (pk == NULL || !VR_EVP_PKEY_set1_DSA(pk, (DSA *)x))
        return 0;
    ret = VR_EVP_PKEY_print_private(bp, pk, off, NULL);
    VR_EVP_PKEY_free(pk);
    return ret;
}

int VR_DSAparams_print(BIO *bp, const DSA *x)
{
    EVP_PKEY *pk;
    int ret;
    pk = VR_EVP_PKEY_new();
    if (pk == NULL || !VR_EVP_PKEY_set1_DSA(pk, (DSA *)x))
        return 0;
    ret = VR_EVP_PKEY_print_params(bp, pk, 4, NULL);
    VR_EVP_PKEY_free(pk);
    return ret;
}
