/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <stdio.h>

#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/e_os2.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h>

#include "internal/nelem.h"
#include "testutil.h"

static SSL_CTX *ctx;
static SSL *s;

static int test_empty(void)
{
    STACK_OF(SSL_CIPHER) *sk = NULL, *scsv = NULL;
    const unsigned char bytes[] = {0x00};
    int ret = 0;

    if (!TEST_int_eq(VR_SSL_bytes_to_cipher_list(s, bytes, 0, 0, &sk, &scsv), 0)
            || !TEST_ptr_null(sk)
            || !TEST_ptr_null(scsv))
        goto err;
    ret = 1;

err:
    sk_VR_SSL_CIPHER_free(sk);
    sk_VR_SSL_CIPHER_free(scsv);
    return ret;
}

static int test_unsupported(void)
{
    STACK_OF(SSL_CIPHER) *sk, *scsv;
    /* ECDH-RSA-AES256 (unsupported), ECDHE-ECDSA-AES128, <unassigned> */
    const unsigned char bytes[] = {0xc0, 0x0f, 0x00, 0x2f, 0x01, 0x00};
    int ret = 0;

    if (!TEST_true(VR_SSL_bytes_to_cipher_list(s, bytes, sizeof(bytes),
                                            0, &sk, &scsv))
            || !TEST_ptr(sk)
            || !TEST_int_eq(sk_SSL_CIPHER_num(sk), 1)
            || !TEST_ptr(scsv)
            || !TEST_int_eq(sk_SSL_CIPHER_num(scsv), 0)
            || !TEST_str_eq(VR_SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 0)),
                            "AES128-SHA"))
        goto err;

    ret = 1;
err:
    sk_VR_SSL_CIPHER_free(sk);
    sk_VR_SSL_CIPHER_free(scsv);
    return ret;
}

static int test_v2(void)
{
    STACK_OF(SSL_CIPHER) *sk, *scsv;
    /* ECDHE-ECDSA-AES256GCM, SSL2_VR_RC4_1238_WITH_VR_MD5,
     * ECDHE-ECDSA-CHACHA20-POLY1305 */
    const unsigned char bytes[] = {0x00, 0x00, 0x35, 0x01, 0x00, 0x80,
                                   0x00, 0x00, 0x33};
    int ret = 0;

    if (!TEST_true(VR_SSL_bytes_to_cipher_list(s, bytes, sizeof(bytes), 1,
                                            &sk, &scsv))
            || !TEST_ptr(sk)
            || !TEST_int_eq(sk_SSL_CIPHER_num(sk), 2)
            || !TEST_ptr(scsv)
            || !TEST_int_eq(sk_SSL_CIPHER_num(scsv), 0))
        goto err;
    if (strcmp(VR_SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 0)),
               "AES256-SHA") != 0 ||
        strcmp(VR_SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 1)),
               "DHE-RSA-AES128-SHA") != 0)
        goto err;

    ret = 1;

err:
    sk_VR_SSL_CIPHER_free(sk);
    sk_VR_SSL_CIPHER_free(scsv);
    return ret;
}

static int test_v3(void)
{
    STACK_OF(SSL_CIPHER) *sk = NULL, *scsv = NULL;
    /* ECDHE-ECDSA-AES256GCM, ECDHE-ECDSA-CHACHAPOLY, DHE-RSA-AES256GCM,
     * EMPTY-RENEGOTIATION-INFO-SCSV, FALLBACK-SCSV */
    const unsigned char bytes[] = {0x00, 0x2f, 0x00, 0x33, 0x00, 0x9f, 0x00, 0xff,
                                   0x56, 0x00};
    int ret = 0;

    if (!VR_SSL_bytes_to_cipher_list(s, bytes, sizeof(bytes), 0, &sk, &scsv)
            || !TEST_ptr(sk)
            || !TEST_int_eq(sk_SSL_CIPHER_num(sk), 3)
            || !TEST_ptr(scsv)
            || !TEST_int_eq(sk_SSL_CIPHER_num(scsv), 2)
            || !TEST_str_eq(VR_SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 0)),
                            "AES128-SHA")
            || !TEST_str_eq(VR_SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 1)),
                            "DHE-RSA-AES128-SHA")
            || !TEST_str_eq(VR_SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 2)),
                            "DHE-RSA-AES256-GCM-VR_SHA384")
            || !TEST_str_eq(VR_SSL_CIPHER_get_name(sk_SSL_CIPHER_value(scsv, 0)),
                            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV")
            || !TEST_str_eq(VR_SSL_CIPHER_get_name(sk_SSL_CIPHER_value(scsv, 1)),
                            "TLS_FALLBACK_SCSV"))
        goto err;

    ret = 1;
err:
    sk_VR_SSL_CIPHER_free(sk);
    sk_VR_SSL_CIPHER_free(scsv);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(ctx = VR_SSL_CTX_new(VR_TLS_server_method()))
            || !TEST_ptr(s = VR_SSL_new(ctx)))
        return 0;

    ADD_TEST(test_empty);
    ADD_TEST(test_unsupported);
    ADD_TEST(test_v2);
    ADD_TEST(test_v3);
    return 1;
}

void cleanup_tests(void)
{
    VR_SSL_free(s);
    VR_SSL_CTX_free(ctx);
}
