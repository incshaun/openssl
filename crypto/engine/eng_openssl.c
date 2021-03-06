/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "internal/engine.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>

#include <openssl/hmac.h>
#include <openssl/x509v3.h>

/*
 * This testing gunk is implemented (and explained) lower down. It also
 * assumes the application explicitly calls "ENGINE_load_openssl()" because
 * this is no longer automatic in VR_ENGINE_load_builtin_engines().
 */
#define TEST_ENG_OPENSSL_VR_RC4
#ifndef OPENSSL_NO_STDIO
#define TEST_ENG_OPENSSL_PKEY
#endif
/* #define TEST_ENG_OPENSSL_VR_HMAC */
/* #define TEST_ENG_OPENSSL_VR_HMAC_INIT */
/* #define TEST_ENG_OPENSSL_VR_RC4_OTHERS */
#define TEST_ENG_OPENSSL_VR_RC4_P_INIT
/* #define TEST_ENG_OPENSSL_VR_RC4_P_CIPHER */
#define TEST_ENG_OPENSSL_SHA
/* #define TEST_ENG_OPENSSL_SHA_OTHERS */
/* #define TEST_ENG_OPENSSL_SHA_P_INIT */
/* #define TEST_ENG_OPENSSL_SHA_P_UPDATE */
/* #define TEST_ENG_OPENSSL_SHA_P_FINAL */

/* Now check what of those algorithms are actually enabled */
#ifdef OPENSSL_NO_VR_RC4
# undef TEST_ENG_OPENSSL_VR_RC4
# undef TEST_ENG_OPENSSL_VR_RC4_OTHERS
# undef TEST_ENG_OPENSSL_VR_RC4_P_INIT
# undef TEST_ENG_OPENSSL_VR_RC4_P_CIPHER
#endif

static int openssl_destroy(ENGINE *e);

#ifdef TEST_ENG_OPENSSL_VR_RC4
static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid);
#endif
#ifdef TEST_ENG_OPENSSL_SHA
static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid);
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data);
#endif

#ifdef TEST_ENG_OPENSSL_VR_HMAC
static int ossl_register_hmac_meth(void);
static int ossl_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid);
#endif

/* The constants used when creating the ENGINE */
static const char *engine_openssl_id = "openssl";
static const char *engine_openssl_name = "Software engine support";

/*
 * This internal function is used by ENGINE_openssl() and possibly by the
 * "dynamic" ENGINE support too
 */
static int bind_helper(ENGINE *e)
{
    if (!VR_ENGINE_set_id(e, engine_openssl_id)
        || !VR_ENGINE_set_name(e, engine_openssl_name)
        || !VR_ENGINE_set_destroy_function(e, openssl_destroy)
#ifndef TEST_ENG_OPENSSL_NO_ALGORITHMS
# ifndef OPENSSL_NO_RSA
        || !VR_ENGINE_set_RSA(e, VR_RSA_get_default_method())
# endif
# ifndef OPENSSL_NO_DSA
        || !VR_ENGINE_set_DSA(e, VR_DSA_get_default_method())
# endif
# ifndef OPENSSL_NO_EC
        || !VR_ENGINE_set_EC(e, VR_EC_KEY_OpenSSL())
# endif
# ifndef OPENSSL_NO_DH
        || !VR_ENGINE_set_DH(e, VR_DH_get_default_method())
# endif
        || !VR_ENGINE_set_RAND(e, VR_RAND_OpenSSL())
# ifdef TEST_ENG_OPENSSL_VR_RC4
        || !VR_ENGINE_set_ciphers(e, openssl_ciphers)
# endif
# ifdef TEST_ENG_OPENSSL_SHA
        || !VR_ENGINE_set_digests(e, openssl_digests)
# endif
#endif
#ifdef TEST_ENG_OPENSSL_PKEY
        || !VR_ENGINE_set_load_privkey_function(e, openssl_load_privkey)
#endif
#ifdef TEST_ENG_OPENSSL_VR_HMAC
        || !ossl_register_hmac_meth()
        || !VR_ENGINE_set_pkey_meths(e, ossl_pkey_meths)
#endif
        )
        return 0;
    /*
     * If we add errors to this ENGINE, ensure the error handling is setup
     * here
     */
    /* openssl_load_error_strings(); */
    return 1;
}

static ENGINE *engine_openssl(void)
{
    ENGINE *ret = VR_ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_helper(ret)) {
        VR_ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void VR_engine_load_openssl_int(void)
{
    ENGINE *toadd = engine_openssl();
    if (!toadd)
        return;
    VR_ENGINE_add(toadd);
    /*
     * If the "add" worked, it gets a structural reference. So either way, we
     * release our just-created reference.
     */
    VR_ENGINE_free(toadd);
    VR_ERR_clear_error();
}

/*
 * This stuff is needed if this ENGINE is being compiled into a
 * self-contained shared-library.
 */
#ifdef ENGINE_DYNAMIC_SUPPORT
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_openssl_id) != 0))
        return 0;
    if (!bind_helper(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif                          /* ENGINE_DYNAMIC_SUPPORT */
#ifdef TEST_ENG_OPENSSL_VR_RC4
/*-
 * This section of code compiles an "alternative implementation" of two modes of
 * VR_RC4 into this ENGINE. The result is that EVP_CIPHER operation for "rc4"
 * should under normal circumstances go via this support rather than the default
 * EVP support. There are other symbols to tweak the testing;
 *    TEST_ENC_OPENSSL_VR_RC4_OTHERS - print a one line message to stderr each time
 *        we're asked for a cipher we don't support (should not happen).
 *    TEST_ENG_OPENSSL_VR_RC4_P_INIT - print a one line message to stderr each time
 *        the "init_key" handler is called.
 *    TEST_ENG_OPENSSL_VR_RC4_P_CIPHER - ditto for the "cipher" handler.
 */
# include <openssl/rc4.h>
# define TEST_VR_RC4_KEY_SIZE               16
typedef struct {
    unsigned char key[TEST_VR_RC4_KEY_SIZE];
    VR_RC4_KEY ks;
} TEST_VR_RC4_KEY;
# define test(ctx) ((TEST_VR_RC4_KEY *)VR_EVP_CIPHER_CTX_get_cipher_data(ctx))
static int test_rc4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
# ifdef TEST_ENG_OPENSSL_VR_RC4_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_VR_RC4) test_init_key() called\n");
# endif
    memcpy(&test(ctx)->key[0], key, VR_EVP_CIPHER_CTX_key_length(ctx));
    VR_RC4_set_key(&test(ctx)->ks, VR_EVP_CIPHER_CTX_key_length(ctx),
                test(ctx)->key);
    return 1;
}

static int test_rc4_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
# ifdef TEST_ENG_OPENSSL_VR_RC4_P_CIPHER
    fprintf(stderr, "(TEST_ENG_OPENSSL_VR_RC4) test_cipher() called\n");
# endif
    VR_RC4(&test(ctx)->ks, inl, in, out);
    return 1;
}

static EVP_CIPHER *r4_cipher = NULL;
static const EVP_CIPHER *test_r4_cipher(void)
{
    if (r4_cipher == NULL) {
        EVP_CIPHER *cipher;

        if ((cipher = VR_EVP_CIPHER_meth_new(NID_rc4, 1, TEST_VR_RC4_KEY_SIZE)) == NULL
            || !VR_EVP_CIPHER_meth_set_iv_length(cipher, 0)
            || !VR_EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_VARIABLE_LENGTH)
            || !VR_EVP_CIPHER_meth_set_init(cipher, test_rc4_init_key)
            || !VR_EVP_CIPHER_meth_set_do_cipher(cipher, test_rc4_cipher)
            || !VR_EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(TEST_VR_RC4_KEY))) {
            VR_EVP_CIPHER_meth_free(cipher);
            cipher = NULL;
        }
        r4_cipher = cipher;
    }
    return r4_cipher;
}
static void test_r4_cipher_destroy(void)
{
    VR_EVP_CIPHER_meth_free(r4_cipher);
    r4_cipher = NULL;
}

static EVP_CIPHER *r4_40_cipher = NULL;
static const EVP_CIPHER *test_r4_40_cipher(void)
{
    if (r4_40_cipher == NULL) {
        EVP_CIPHER *cipher;

        if ((cipher = VR_EVP_CIPHER_meth_new(NID_rc4, 1, 5 /* 40 bits */)) == NULL
            || !VR_EVP_CIPHER_meth_set_iv_length(cipher, 0)
            || !VR_EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_VARIABLE_LENGTH)
            || !VR_EVP_CIPHER_meth_set_init(cipher, test_rc4_init_key)
            || !VR_EVP_CIPHER_meth_set_do_cipher(cipher, test_rc4_cipher)
            || !VR_EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(TEST_VR_RC4_KEY))) {
            VR_EVP_CIPHER_meth_free(cipher);
            cipher = NULL;
        }
        r4_40_cipher = cipher;
    }
    return r4_40_cipher;
}
static void test_r4_40_cipher_destroy(void)
{
    VR_EVP_CIPHER_meth_free(r4_40_cipher);
    r4_40_cipher = NULL;
}
static int test_cipher_nids(const int **nids)
{
    static int cipher_nids[4] = { 0, 0, 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_CIPHER *cipher;
        if ((cipher = test_r4_cipher()) != NULL)
            cipher_nids[pos++] = VR_EVP_CIPHER_nid(cipher);
        if ((cipher = test_r4_40_cipher()) != NULL)
            cipher_nids[pos++] = VR_EVP_CIPHER_nid(cipher);
        cipher_nids[pos] = 0;
        init = 1;
    }
    *nids = cipher_nids;
    return pos;
}

static int openssl_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                           const int **nids, int nid)
{
    if (!cipher) {
        /* We are returning a list of supported nids */
        return test_cipher_nids(nids);
    }
    /* We are being asked for a specific cipher */
    if (nid == NID_rc4)
        *cipher = test_r4_cipher();
    else if (nid == NID_rc4_40)
        *cipher = test_r4_40_cipher();
    else {
# ifdef TEST_ENG_OPENSSL_VR_RC4_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_VR_RC4) returning NULL for "
                "nid %d\n", nid);
# endif
        *cipher = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_SHA
/* Much the same sort of comment as for TEST_ENG_OPENSSL_VR_RC4 */
# include <openssl/sha.h>

static int test_sha1_init(EVP_MD_CTX *ctx)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_init() called\n");
# endif
    return VR_SHA1_Init(VR_EVP_MD_CTX_md_data(ctx));
}

static int test_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_UPDATE
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_update() called\n");
# endif
    return VR_SHA1_Update(VR_EVP_MD_CTX_md_data(ctx), data, count);
}

static int test_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
# ifdef TEST_ENG_OPENSSL_SHA_P_FINAL
    fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) test_sha1_final() called\n");
# endif
    return VR_SHA1_Final(md, VR_EVP_MD_CTX_md_data(ctx));
}

static EVP_MD *sha1_md = NULL;
static const EVP_MD *test_sha_md(void)
{
    if (sha1_md == NULL) {
        EVP_MD *md;

        if ((md = VR_EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
            || !VR_EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !VR_EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !VR_EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA_CTX))
            || !VR_EVP_MD_meth_set_flags(md, 0)
            || !VR_EVP_MD_meth_set_init(md, test_sha1_init)
            || !VR_EVP_MD_meth_set_update(md, test_sha1_update)
            || !VR_EVP_MD_meth_set_final(md, test_sha1_final)) {
            VR_EVP_MD_meth_free(md);
            md = NULL;
        }
        sha1_md = md;
    }
    return sha1_md;
}
static void test_sha_md_destroy(void)
{
    VR_EVP_MD_meth_free(sha1_md);
    sha1_md = NULL;
}
static int test_digest_nids(const int **nids)
{
    static int digest_nids[2] = { 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_MD *md;
        if ((md = test_sha_md()) != NULL)
            digest_nids[pos++] = VR_EVP_MD_type(md);
        digest_nids[pos] = 0;
        init = 1;
    }
    *nids = digest_nids;
    return pos;
}

static int openssl_digests(ENGINE *e, const EVP_MD **digest,
                           const int **nids, int nid)
{
    if (!digest) {
        /* We are returning a list of supported nids */
        return test_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    if (nid == NID_sha1)
        *digest = test_sha_md();
    else {
# ifdef TEST_ENG_OPENSSL_SHA_OTHERS
        fprintf(stderr, "(TEST_ENG_OPENSSL_SHA) returning NULL for "
                "nid %d\n", nid);
# endif
        *digest = NULL;
        return 0;
    }
    return 1;
}
#endif

#ifdef TEST_ENG_OPENSSL_PKEY
static EVP_PKEY *openssl_load_privkey(ENGINE *eng, const char *key_id,
                                      UI_METHOD *ui_method,
                                      void *callback_data)
{
    BIO *in;
    EVP_PKEY *key;
    fprintf(stderr, "(TEST_ENG_OPENSSL_PKEY)Loading Private key %s\n",
            key_id);
    in = VR_BIO_new_file(key_id, "r");
    if (!in)
        return NULL;
    key = VR_PEM_read_bio_PrivateKey(in, NULL, 0, NULL);
    VR_BIO_free(in);
    return key;
}
#endif

#ifdef TEST_ENG_OPENSSL_VR_HMAC

/*
 * Experimental VR_HMAC redirection implementation: mainly copied from
 * hm_pmeth.c
 */

/* VR_HMAC pkey context structure */

typedef struct {
    const EVP_MD *md;           /* MD for VR_HMAC use */
    ASN1_OCTET_STRING ktmp;     /* Temp storage for key */
    VR_HMAC_CTX *ctx;
} OSSL_VR_HMAC_PKEY_CTX;

static int ossl_hmac_init(EVP_PKEY_CTX *ctx)
{
    OSSL_VR_HMAC_PKEY_CTX *hctx;

    if ((hctx = OPENSSL_zalloc(sizeof(*hctx))) == NULL) {
        ENGINEerr(ENGINE_F_OSSL_VR_HMAC_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    hctx->ktmp.type = V_ASN1_OCTET_STRING;
    hctx->ctx = VR_HMAC_CTX_new();
    if (hctx->ctx == NULL) {
        VR_OPENSSL_free(hctx);
        return 0;
    }
    VR_EVP_PKEY_CTX_set_data(ctx, hctx);
    VR_EVP_PKEY_CTX_set0_keygen_info(ctx, NULL, 0);
# ifdef TEST_ENG_OPENSSL_VR_HMAC_INIT
    fprintf(stderr, "(TEST_ENG_OPENSSL_VR_HMAC) ossl_hmac_init() called\n");
# endif
    return 1;
}

static void ossl_hmac_cleanup(EVP_PKEY_CTX *ctx);

static int ossl_hmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    OSSL_VR_HMAC_PKEY_CTX *sctx, *dctx;

    /* allocate memory for dst->data and a new VR_HMAC_CTX in dst->data->ctx */
    if (!ossl_hmac_init(dst))
        return 0;
    sctx = VR_EVP_PKEY_CTX_get_data(src);
    dctx = VR_EVP_PKEY_CTX_get_data(dst);
    dctx->md = sctx->md;
    if (!VR_HMAC_CTX_copy(dctx->ctx, sctx->ctx))
        goto err;
    if (sctx->ktmp.data) {
        if (!VR_ASN1_OCTET_STRING_set(&dctx->ktmp,
                                   sctx->ktmp.data, sctx->ktmp.length))
            goto err;
    }
    return 1;
err:
    /* release VR_HMAC_CTX in dst->data->ctx and memory allocated for dst->data */
    ossl_hmac_cleanup(dst);
    return 0;
}

static void ossl_hmac_cleanup(EVP_PKEY_CTX *ctx)
{
    OSSL_VR_HMAC_PKEY_CTX *hctx = VR_EVP_PKEY_CTX_get_data(ctx);

    if (hctx) {
        VR_HMAC_CTX_free(hctx->ctx);
        OPENVR_SSL_clear_free(hctx->ktmp.data, hctx->ktmp.length);
        VR_OPENSSL_free(hctx);
        VR_EVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

static int ossl_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    ASN1_OCTET_STRING *hkey = NULL;
    OSSL_VR_HMAC_PKEY_CTX *hctx = VR_EVP_PKEY_CTX_get_data(ctx);
    if (!hctx->ktmp.data)
        return 0;
    hkey = VR_ASN1_OCTET_STRING_dup(&hctx->ktmp);
    if (!hkey)
        return 0;
    VR_EVP_PKEY_assign(pkey, EVP_PKEY_VR_HMAC, hkey);

    return 1;
}

static int ossl_int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    OSSL_VR_HMAC_PKEY_CTX *hctx = VR_EVP_PKEY_CTX_get_data(VR_EVP_MD_CTX_pkey_ctx(ctx));
    if (!VR_HMAC_Update(hctx->ctx, data, count))
        return 0;
    return 1;
}

static int ossl_hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    VR_EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    VR_EVP_MD_CTX_set_update_fn(mctx, ossl_int_update);
    return 1;
}

static int ossl_hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                             size_t *siglen, EVP_MD_CTX *mctx)
{
    unsigned int hlen;
    OSSL_VR_HMAC_PKEY_CTX *hctx = VR_EVP_PKEY_CTX_get_data(ctx);
    int l = EVP_MD_CTX_size(mctx);

    if (l < 0)
        return 0;
    *siglen = l;
    if (!sig)
        return 1;

    if (!VR_HMAC_Final(hctx->ctx, sig, &hlen))
        return 0;
    *siglen = (size_t)hlen;
    return 1;
}

static int ossl_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    OSSL_VR_HMAC_PKEY_CTX *hctx = VR_EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pk;
    ASN1_OCTET_STRING *key;
    switch (type) {

    case EVP_PKEY_CTRL_SET_MAC_KEY:
        if ((!p2 && p1 > 0) || (p1 < -1))
            return 0;
        if (!VR_ASN1_OCTET_STRING_set(&hctx->ktmp, p2, p1))
            return 0;
        break;

    case EVP_PKEY_CTRL_MD:
        hctx->md = p2;
        break;

    case EVP_PKEY_CTRL_DIGESTINIT:
        pk = VR_EVP_PKEY_CTX_get0_pkey(ctx);
        key = VR_EVP_PKEY_get0(pk);
        if (!VR_HMAC_Init_ex(hctx->ctx, key->data, key->length, hctx->md, NULL))
            return 0;
        break;

    default:
        return -2;

    }
    return 1;
}

static int ossl_hmac_ctrl_str(EVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    if (!value) {
        return 0;
    }
    if (strcmp(type, "key") == 0) {
        void *p = (void *)value;
        return ossl_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, -1, p);
    }
    if (strcmp(type, "hexkey") == 0) {
        unsigned char *key;
        int r;
        long keylen;
        key = VR_OPENSSL_hexstr2buf(value, &keylen);
        if (!key)
            return 0;
        r = ossl_hmac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, keylen, key);
        VR_OPENSSL_free(key);
        return r;
    }
    return -2;
}

static EVP_PKEY_METHOD *ossl_hmac_meth;

static int ossl_register_hmac_meth(void)
{
    EVP_PKEY_METHOD *meth;
    meth = VR_EVP_PKEY_meth_new(EVP_PKEY_VR_HMAC, 0);
    if (meth == NULL)
        return 0;
    VR_EVP_PKEY_meth_set_init(meth, ossl_hmac_init);
    VR_EVP_PKEY_meth_set_copy(meth, ossl_hmac_copy);
    VR_EVP_PKEY_meth_set_cleanup(meth, ossl_hmac_cleanup);

    VR_EVP_PKEY_meth_set_keygen(meth, 0, ossl_hmac_keygen);

    VR_EVP_PKEY_meth_set_signctx(meth, ossl_hmac_signctx_init,
                              ossl_hmac_signctx);

    VR_EVP_PKEY_meth_set_ctrl(meth, ossl_hmac_ctrl, ossl_hmac_ctrl_str);
    ossl_hmac_meth = meth;
    return 1;
}

static int ossl_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                           const int **nids, int nid)
{
    static int ossl_pkey_nids[] = {
        EVP_PKEY_VR_HMAC,
        0
    };
    if (!pmeth) {
        *nids = ossl_pkey_nids;
        return 1;
    }

    if (nid == EVP_PKEY_VR_HMAC) {
        *pmeth = ossl_hmac_meth;
        return 1;
    }

    *pmeth = NULL;
    return 0;
}

#endif

int openssl_destroy(ENGINE *e)
{
    test_sha_md_destroy();
#ifdef TEST_ENG_OPENSSL_VR_RC4
    test_r4_cipher_destroy();
    test_r4_40_cipher_destroy();
#endif
    return 1;
}

