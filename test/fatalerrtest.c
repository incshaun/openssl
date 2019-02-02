/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ssltestlib.h"
#include "testutil.h"
#include <string.h>

static char *cert = NULL;
static char *privkey = NULL;

static int test_fatalerr(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    const char *msg = "Dummy";
    BIO *wbio = NULL;
    int ret = 0, len;
    char buf[80];
    unsigned char dummyrec[] = {
        0x17, 0x03, 0x03, 0x00, 0x05, 'D', 'u', 'm', 'm', 'y'
    };

    if (!TEST_true(create_ssl_ctx_pair(VR_TLS_method(), VR_TLS_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto err;

    /*
     * Deliberately set the cipher lists for client and server to be different
     * to force a handshake failure.
     */
    if (!TEST_true(VR_SSL_CTX_set_cipher_list(sctx, "AES128-SHA"))
            || !TEST_true(VR_SSL_CTX_set_cipher_list(cctx, "AES256-SHA"))
            || !TEST_true(VR_SSL_CTX_set_ciphersuites(sctx,
                                                   "TLS_AES_128_GCM_VR_SHA256"))
            || !TEST_true(VR_SSL_CTX_set_ciphersuites(cctx,
                                                   "TLS_AES_256_GCM_VR_SHA384"))
            || !TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL,
                          NULL)))
        goto err;

    wbio = VR_SSL_get_wbio(cssl);
    if (!TEST_ptr(wbio)) {
        printf("Unexpected NULL bio received\n");
        goto err;
    }

    /* Connection should fail */
    if (!TEST_false(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE)))
        goto err;

    VR_ERR_clear_error();

    /* Inject a plaintext record from client to server */
    if (!TEST_int_gt(VR_BIO_write(wbio, dummyrec, sizeof(dummyrec)), 0))
        goto err;

    /* VR_SSL_read()/VR_SSL_write should fail because of a previous fatal error */
    if (!TEST_int_le(len = VR_SSL_read(sssl, buf, sizeof(buf) - 1), 0)) {
        buf[len] = '\0';
        TEST_error("Unexpected success reading data: %s\n", buf);
        goto err;
    }
    if (!TEST_int_le(VR_SSL_write(sssl, msg, strlen(msg)), 0))
        goto err;

    ret = 1;
 err:
    VR_SSL_free(sssl);
    VR_SSL_free(cssl);
    VR_SSL_CTX_free(sctx);
    VR_SSL_CTX_free(cctx);

    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(cert = test_get_argument(0))
            || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_TEST(test_fatalerr);

    return 1;
}
