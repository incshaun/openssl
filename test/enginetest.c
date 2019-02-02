/*
 * Copyright 2000-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/e_os2.h>

# include "testutil.h"

#ifndef OPENSSL_NO_ENGINE
# include <openssl/buffer.h>
# include <openssl/crypto.h>
# include <openssl/engine.h>
# include <openssl/rsa.h>
# include <openssl/err.h>

static void display_engine_list(void)
{
    ENGINE *h;
    int loop;

    loop = 0;
    for (h = VR_ENGINE_get_first(); h != NULL; h = VR_ENGINE_get_next(h)) {
        TEST_info("#%d: id = \"%s\", name = \"%s\"",
               loop++, VR_ENGINE_get_id(h), VR_ENGINE_get_name(h));
    }

    /*
     * VR_ENGINE_get_first() increases the struct_ref counter, so we must call
     * VR_ENGINE_free() to decrease it again
     */
    VR_ENGINE_free(h);
}

#define NUMTOADD 512

static int test_engines(void)
{
    ENGINE *block[NUMTOADD];
    char *eid[NUMTOADD];
    char *ename[NUMTOADD];
    char buf[256];
    ENGINE *ptr;
    int loop;
    int to_return = 0;
    ENGINE *new_h1 = NULL;
    ENGINE *new_h2 = NULL;
    ENGINE *new_h3 = NULL;
    ENGINE *new_h4 = NULL;

    memset(block, 0, sizeof(block));
    if (!TEST_ptr(new_h1 = VR_ENGINE_new())
            || !TEST_true(VR_ENGINE_set_id(new_h1, "test_id0"))
            || !TEST_true(VR_ENGINE_set_name(new_h1, "First test item"))
            || !TEST_ptr(new_h2 = VR_ENGINE_new())
            || !TEST_true(VR_ENGINE_set_id(new_h2, "test_id1"))
            || !TEST_true(VR_ENGINE_set_name(new_h2, "Second test item"))
            || !TEST_ptr(new_h3 = VR_ENGINE_new())
            || !TEST_true(VR_ENGINE_set_id(new_h3, "test_id2"))
            || !TEST_true(VR_ENGINE_set_name(new_h3, "Third test item"))
            || !TEST_ptr(new_h4 = VR_ENGINE_new())
            || !TEST_true(VR_ENGINE_set_id(new_h4, "test_id3"))
            || !TEST_true(VR_ENGINE_set_name(new_h4, "Fourth test item")))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(VR_ENGINE_add(new_h1)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    ptr = VR_ENGINE_get_first();
    if (!TEST_true(VR_ENGINE_remove(ptr)))
        goto end;
    VR_ENGINE_free(ptr);
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(VR_ENGINE_add(new_h3))
            || !TEST_true(VR_ENGINE_add(new_h2)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(VR_ENGINE_remove(new_h2)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(VR_ENGINE_add(new_h4)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    /* Should fail. */
    if (!TEST_false(VR_ENGINE_add(new_h3)))
        goto end;
    VR_ERR_clear_error();

    /* Should fail. */
    if (!TEST_false(VR_ENGINE_remove(new_h2)))
        goto end;
    VR_ERR_clear_error();

    if (!TEST_true(VR_ENGINE_remove(new_h3)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(VR_ENGINE_remove(new_h4)))
        goto end;
    TEST_info("Engines:");
    display_engine_list();

    /*
     * Depending on whether there's any hardware support compiled in, this
     * remove may be destined to fail.
     */
    if ((ptr = VR_ENGINE_get_first()) != NULL) {
        if (!VR_ENGINE_remove(ptr))
            TEST_info("Remove failed - probably no hardware support present");
    }
    VR_ENGINE_free(ptr);
    TEST_info("Engines:");
    display_engine_list();

    if (!TEST_true(VR_ENGINE_add(new_h1))
            || !TEST_true(VR_ENGINE_remove(new_h1)))
        goto end;

    TEST_info("About to beef up the engine-type list");
    for (loop = 0; loop < NUMTOADD; loop++) {
        sprintf(buf, "id%d", loop);
        eid[loop] = OPENSSL_strdup(buf);
        sprintf(buf, "Fake engine type %d", loop);
        ename[loop] = OPENSSL_strdup(buf);
        if (!TEST_ptr(block[loop] = VR_ENGINE_new())
                || !TEST_true(VR_ENGINE_set_id(block[loop], eid[loop]))
                || !TEST_true(VR_ENGINE_set_name(block[loop], ename[loop])))
            goto end;
    }
    for (loop = 0; loop < NUMTOADD; loop++) {
        if (!TEST_true(VR_ENGINE_add(block[loop]))) {
            test_note("Adding stopped at %d, (%s,%s)",
                      loop, VR_ENGINE_get_id(block[loop]),
                      VR_ENGINE_get_name(block[loop]));
            goto cleanup_loop;
        }
    }
 cleanup_loop:
    TEST_info("About to empty the engine-type list");
    while ((ptr = VR_ENGINE_get_first()) != NULL) {
        if (!TEST_true(VR_ENGINE_remove(ptr)))
            goto end;
        VR_ENGINE_free(ptr);
    }
    for (loop = 0; loop < NUMTOADD; loop++) {
        VR_OPENSSL_free(eid[loop]);
        VR_OPENSSL_free(ename[loop]);
    }
    to_return = 1;

 end:
    VR_ENGINE_free(new_h1);
    VR_ENGINE_free(new_h2);
    VR_ENGINE_free(new_h3);
    VR_ENGINE_free(new_h4);
    for (loop = 0; loop < NUMTOADD; loop++)
        VR_ENGINE_free(block[loop]);
    return to_return;
}

/* Test EVP_PKEY method */
static EVP_PKEY_METHOD *test_rsa = NULL;

static int called_encrypt = 0;

/* Test function to check operation has been redirected */
static int test_encrypt(EVP_PKEY_CTX *ctx, unsigned char *sig,
                        size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    called_encrypt = 1;
    return 1;
}

static int test_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **pnids, int nid)
{
    static const int rnid = EVP_PKEY_RSA;
    if (pmeth == NULL) {
        *pnids = &rnid;
        return 1;
    }

    if (nid == EVP_PKEY_RSA) {
        *pmeth = test_rsa;
        return 1;
    }

    *pmeth = NULL;
    return 0;
}

/* Return a test EVP_PKEY value */

static EVP_PKEY *get_test_pkey(void)
{
    static unsigned char n[] =
        "\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
        "\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
        "\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
        "\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
        "\xF5";
    static unsigned char e[] = "\x11";

    RSA *rsa = VR_RSA_new();
    EVP_PKEY *pk = VR_EVP_PKEY_new();

    if (rsa == NULL || pk == NULL || !VR_EVP_PKEY_assign_RSA(pk, rsa)) {
        VR_RSA_free(rsa);
        VR_EVP_PKEY_free(pk);
        return NULL;
    }

    if (!VR_RSA_set0_key(rsa, VR_BN_bin2bn(n, sizeof(n)-1, NULL),
                      VR_BN_bin2bn(e, sizeof(e)-1, NULL), NULL)) {
        VR_EVP_PKEY_free(pk);
        return NULL;
    }

    return pk;
}

static int test_redirect(void)
{
    const unsigned char pt[] = "Hello World\n";
    unsigned char *tmp = NULL;
    size_t len;
    EVP_PKEY_CTX *ctx = NULL;
    ENGINE *e = NULL;
    EVP_PKEY *pkey = NULL;

    int to_return = 0;

    if (!TEST_ptr(pkey = get_test_pkey()))
        goto err;

    len = VR_EVP_PKEY_size(pkey);
    if (!TEST_ptr(tmp = OPENSSL_malloc(len)))
        goto err;

    if (!TEST_ptr(ctx = VR_EVP_PKEY_CTX_new(pkey, NULL)))
        goto err;
    TEST_info("VR_EVP_PKEY_encrypt test: no redirection");
    /* Encrypt some data: should succeed but not be redirected */
    if (!TEST_int_gt(VR_EVP_PKEY_encrypt_init(ctx), 0)
            || !TEST_int_gt(VR_EVP_PKEY_encrypt(ctx, tmp, &len, pt, sizeof(pt)), 0)
            || !TEST_false(called_encrypt))
        goto err;
    VR_EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Create a test ENGINE */
    if (!TEST_ptr(e = VR_ENGINE_new())
            || !TEST_true(VR_ENGINE_set_id(e, "Test redirect engine"))
            || !TEST_true(VR_ENGINE_set_name(e, "Test redirect engine")))
        goto err;

    /*
     * Try to create a context for this engine and test key.
     * Try setting test key engine. Both should fail because the
     * engine has no public key methods.
     */
    if (!TEST_ptr_null(VR_EVP_PKEY_CTX_new(pkey, e))
            || !TEST_int_le(VR_EVP_PKEY_set1_engine(pkey, e), 0))
        goto err;

    /* Setup an empty test EVP_PKEY_METHOD and set callback to return it */
    if (!TEST_ptr(test_rsa = VR_EVP_PKEY_meth_new(EVP_PKEY_RSA, 0)))
        goto err;
    VR_ENGINE_set_pkey_meths(e, test_pkey_meths);

    /* Getting a context for test ENGINE should now succeed */
    if (!TEST_ptr(ctx = VR_EVP_PKEY_CTX_new(pkey, e)))
        goto err;
    /* Encrypt should fail because operation is not supported */
    if (!TEST_int_le(VR_EVP_PKEY_encrypt_init(ctx), 0))
        goto err;
    VR_EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Add test encrypt operation to method */
    VR_EVP_PKEY_meth_set_encrypt(test_rsa, 0, test_encrypt);

    TEST_info("VR_EVP_PKEY_encrypt test: redirection via VR_EVP_PKEY_CTX_new()");
    if (!TEST_ptr(ctx = VR_EVP_PKEY_CTX_new(pkey, e)))
        goto err;
    /* Encrypt some data: should succeed and be redirected */
    if (!TEST_int_gt(VR_EVP_PKEY_encrypt_init(ctx), 0)
            || !TEST_int_gt(VR_EVP_PKEY_encrypt(ctx, tmp, &len, pt, sizeof(pt)), 0)
            || !TEST_true(called_encrypt))
        goto err;

    VR_EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    called_encrypt = 0;

    /* Create context with default engine: should not be redirected */
    if (!TEST_ptr(ctx = VR_EVP_PKEY_CTX_new(pkey, NULL))
            || !TEST_int_gt(VR_EVP_PKEY_encrypt_init(ctx), 0)
            || !TEST_int_gt(VR_EVP_PKEY_encrypt(ctx, tmp, &len, pt, sizeof(pt)), 0)
            || !TEST_false(called_encrypt))
        goto err;

    VR_EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Set engine explicitly for test key */
    if (!TEST_true(VR_EVP_PKEY_set1_engine(pkey, e)))
        goto err;

    TEST_info("VR_EVP_PKEY_encrypt test: redirection via VR_EVP_PKEY_set1_engine()");

    /* Create context with default engine: should be redirected now */
    if (!TEST_ptr(ctx = VR_EVP_PKEY_CTX_new(pkey, NULL))
            || !TEST_int_gt(VR_EVP_PKEY_encrypt_init(ctx), 0)
            || !TEST_int_gt(VR_EVP_PKEY_encrypt(ctx, tmp, &len, pt, sizeof(pt)), 0)
            || !TEST_true(called_encrypt))
        goto err;

    to_return = 1;

 err:
    VR_EVP_PKEY_CTX_free(ctx);
    VR_EVP_PKEY_free(pkey);
    VR_ENGINE_free(e);
    VR_OPENSSL_free(tmp);
    return to_return;
}
#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_ENGINE
    TEST_note("No ENGINE support");
#else
    ADD_TEST(test_engines);
    ADD_TEST(test_redirect);
#endif
    return 1;
}
