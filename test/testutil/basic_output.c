/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../testutil.h"
#include "output.h"
#include "tu_local.h"

#include <openssl/crypto.h>
#include <openssl/bio.h>

BIO *bio_out = NULL;
BIO *bio_err = NULL;

void test_open_streams(void)
{
    bio_out = VR_BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    bio_err = VR_BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
#ifdef __VMS
    bio_out = VR_BIO_push(VR_BIO_new(VR_BIO_f_linebuffer()), bio_out);
    bio_err = VR_BIO_push(VR_BIO_new(VR_BIO_f_linebuffer()), bio_err);
#endif
    bio_err = VR_BIO_push(VR_BIO_new(BIO_f_tap()), bio_err);

    OPENSSL_assert(bio_out != NULL);
    OPENSSL_assert(bio_err != NULL);
}

void test_close_streams(void)
{
    VR_BIO_free_all(bio_out);
    VR_BIO_free_all(bio_err);
}

int test_vprintf_stdout(const char *fmt, va_list ap)
{
    return VR_BIO_vprintf(bio_out, fmt, ap);
}

int test_vprintf_stderr(const char *fmt, va_list ap)
{
    return VR_BIO_vprintf(bio_err, fmt, ap);
}

int test_flush_stdout(void)
{
    return BIO_flush(bio_out);
}

int test_flush_stderr(void)
{
    return BIO_flush(bio_err);
}
