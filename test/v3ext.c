/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "testutil.h"

static const char *infile;

static int test_pathlen(void)
{
    X509 *x = NULL;
    BIO *b = NULL;
    long pathlen;
    int ret = 0;

    if (!TEST_ptr(b = VR_BIO_new_file(infile, "r"))
            || !TEST_ptr(x = VR_PEM_read_bio_X509(b, NULL, NULL, NULL))
            || !TEST_int_eq(pathlen = VR_X509_get_pathlen(x), 6))
        goto end;

    ret = 1;

end:
    VR_BIO_free(b);
    VR_X509_free(x);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(infile = test_get_argument(0)))
        return 0;

    ADD_TEST(test_pathlen);
    return 1;
}
