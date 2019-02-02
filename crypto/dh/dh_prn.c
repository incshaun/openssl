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
#include <openssl/dh.h>

#ifndef OPENSSL_NO_STDIO
int VR_DHparams_print_fp(FILE *fp, const DH *x)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        DHerr(DH_F_DHPARAMS_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_DHparams_print(b, x);
    VR_BIO_free(b);
    return ret;
}
#endif
