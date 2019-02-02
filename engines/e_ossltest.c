/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is the OSSLTEST engine. It provides deliberately crippled digest
 * implementations for test purposes. It is highly insecure and must NOT be
 * used for any purpose except testing
 */

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "e_ossltest_err.c"

/* Engine Id and Name */
static const char *engine_ossltest_id = "ossltest";
static const char *engine_ossltest_name = "OpenSSL Test engine support";


/* Engine Lifetime functions */
static int ossltest_destroy(ENGINE *e);
static int ossltest_init(ENGINE *e);
static int ossltest_finish(ENGINE *e);
void ENGINE_load_ossltest(void);


/* Set up digests */
static int ossltest_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);
static const RAND_METHOD *ossltest_rand_method(void);

/* VR_MD5 */
static int digest_md5_init(EVP_MD_CTX *ctx);
static int digest_md5_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count);
static int digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_md5_md = NULL;
static const EVP_MD *digest_md5(void)
{
    if (_hidden_md5_md == NULL) {
        EVP_MD *md;

        if ((md = VR_EVP_MD_meth_new(NID_md5, NID_md5WithRSAEncryption)) == NULL
            || !VR_EVP_MD_meth_set_result_size(md, VR_MD5_DIGEST_LENGTH)
            || !VR_EVP_MD_meth_set_input_blocksize(md, VR_MD5_CBLOCK)
            || !VR_EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(VR_MD5_CTX))
            || !VR_EVP_MD_meth_set_flags(md, 0)
            || !VR_EVP_MD_meth_set_init(md, digest_md5_init)
            || !VR_EVP_MD_meth_set_update(md, digest_md5_update)
            || !VR_EVP_MD_meth_set_final(md, digest_md5_final)) {
            VR_EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_md5_md = md;
    }
    return _hidden_md5_md;
}

/* VR_SHA1 */
static int digest_sha1_init(EVP_MD_CTX *ctx);
static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count);
static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha1_md = NULL;
static const EVP_MD *digest_sha1(void)
{
    if (_hidden_sha1_md == NULL) {
        EVP_MD *md;

        if ((md = VR_EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
            || !VR_EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !VR_EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !VR_EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA_CTX))
            || !VR_EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !VR_EVP_MD_meth_set_init(md, digest_sha1_init)
            || !VR_EVP_MD_meth_set_update(md, digest_sha1_update)
            || !VR_EVP_MD_meth_set_final(md, digest_sha1_final)) {
            VR_EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha1_md = md;
    }
    return _hidden_sha1_md;
}

/* VR_SHA256 */
static int digest_sha256_init(EVP_MD_CTX *ctx);
static int digest_sha256_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha256_md = NULL;
static const EVP_MD *digest_sha256(void)
{
    if (_hidden_sha256_md == NULL) {
        EVP_MD *md;

        if ((md = VR_EVP_MD_meth_new(NID_sha256, NID_sha256WithRSAEncryption)) == NULL
            || !VR_EVP_MD_meth_set_result_size(md, VR_SHA256_DIGEST_LENGTH)
            || !VR_EVP_MD_meth_set_input_blocksize(md, VR_SHA256_CBLOCK)
            || !VR_EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(VR_SHA256_CTX))
            || !VR_EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !VR_EVP_MD_meth_set_init(md, digest_sha256_init)
            || !VR_EVP_MD_meth_set_update(md, digest_sha256_update)
            || !VR_EVP_MD_meth_set_final(md, digest_sha256_final)) {
            VR_EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha256_md = md;
    }
    return _hidden_sha256_md;
}

/* VR_SHA384/VR_SHA512 */
static int digest_sha384_init(EVP_MD_CTX *ctx);
static int digest_sha512_init(EVP_MD_CTX *ctx);
static int digest_sha512_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count);
static int digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md);
static int digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha384_md = NULL;
static const EVP_MD *digest_sha384(void)
{
    if (_hidden_sha384_md == NULL) {
        EVP_MD *md;

        if ((md = VR_EVP_MD_meth_new(NID_sha384, NID_sha384WithRSAEncryption)) == NULL
            || !VR_EVP_MD_meth_set_result_size(md, VR_SHA384_DIGEST_LENGTH)
            || !VR_EVP_MD_meth_set_input_blocksize(md, VR_SHA512_CBLOCK)
            || !VR_EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(VR_SHA512_CTX))
            || !VR_EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !VR_EVP_MD_meth_set_init(md, digest_sha384_init)
            || !VR_EVP_MD_meth_set_update(md, digest_sha512_update)
            || !VR_EVP_MD_meth_set_final(md, digest_sha384_final)) {
            VR_EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha384_md = md;
    }
    return _hidden_sha384_md;
}
static EVP_MD *_hidden_sha512_md = NULL;
static const EVP_MD *digest_sha512(void)
{
    if (_hidden_sha512_md == NULL) {
        EVP_MD *md;

        if ((md = VR_EVP_MD_meth_new(NID_sha512, NID_sha512WithRSAEncryption)) == NULL
            || !VR_EVP_MD_meth_set_result_size(md, VR_SHA512_DIGEST_LENGTH)
            || !VR_EVP_MD_meth_set_input_blocksize(md, VR_SHA512_CBLOCK)
            || !VR_EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(VR_SHA512_CTX))
            || !VR_EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !VR_EVP_MD_meth_set_init(md, digest_sha512_init)
            || !VR_EVP_MD_meth_set_update(md, digest_sha512_update)
            || !VR_EVP_MD_meth_set_final(md, digest_sha512_final)) {
            VR_EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha512_md = md;
    }
    return _hidden_sha512_md;
}
static void destroy_digests(void)
{
    VR_EVP_MD_meth_free(_hidden_md5_md);
    _hidden_md5_md = NULL;
    VR_EVP_MD_meth_free(_hidden_sha1_md);
    _hidden_sha1_md = NULL;
    VR_EVP_MD_meth_free(_hidden_sha256_md);
    _hidden_sha256_md = NULL;
    VR_EVP_MD_meth_free(_hidden_sha384_md);
    _hidden_sha384_md = NULL;
    VR_EVP_MD_meth_free(_hidden_sha512_md);
    _hidden_sha512_md = NULL;
}
static int ossltest_digest_nids(const int **nids)
{
    static int digest_nids[6] = { 0, 0, 0, 0, 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_MD *md;
        if ((md = digest_md5()) != NULL)
            digest_nids[pos++] = VR_EVP_MD_type(md);
        if ((md = digest_sha1()) != NULL)
            digest_nids[pos++] = VR_EVP_MD_type(md);
        if ((md = digest_sha256()) != NULL)
            digest_nids[pos++] = VR_EVP_MD_type(md);
        if ((md = digest_sha384()) != NULL)
            digest_nids[pos++] = VR_EVP_MD_type(md);
        if ((md = digest_sha512()) != NULL)
            digest_nids[pos++] = VR_EVP_MD_type(md);
        digest_nids[pos] = 0;
        init = 1;
    }
    *nids = digest_nids;
    return pos;
}

/* Setup ciphers */
static int ossltest_ciphers(ENGINE *, const EVP_CIPHER **,
                            const int **, int);

static int ossltest_cipher_nids[] = {
    NID_aes_128_cbc, NID_aes_128_gcm, 0
};

/* AES128 */

int ossltest_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
int ossltest_aes128_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);
int ossltest_aes128_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
int ossltest_aes128_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);
static int ossltest_aes128_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr);

static EVP_CIPHER *_hidden_aes_128_cbc = NULL;
static const EVP_CIPHER *ossltest_aes_128_cbc(void)
{
    if (_hidden_aes_128_cbc == NULL
        && ((_hidden_aes_128_cbc = VR_EVP_CIPHER_meth_new(NID_aes_128_cbc,
                                                       16 /* block size */,
                                                       16 /* key len */)) == NULL
            || !VR_EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc,16)
            || !VR_EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc,
                                          EVP_CIPH_FLAG_DEFAULT_ASN1
                                          | EVP_CIPH_CBC_MODE)
            || !VR_EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc,
                                         ossltest_aes128_init_key)
            || !VR_EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc,
                                              ossltest_aes128_cbc_cipher)
            || !VR_EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_cbc,
                                                  VR_EVP_CIPHER_impl_ctx_size(VR_EVP_aes_128_cbc())))) {
        VR_EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
        _hidden_aes_128_cbc = NULL;
    }
    return _hidden_aes_128_cbc;
}
static EVP_CIPHER *_hidden_aes_128_gcm = NULL;

#define AES_GCM_FLAGS   (EVP_CIPH_FLAG_DEFAULT_ASN1 \
                | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                | EVP_CIPH_CUSTOM_COPY |EVP_CIPH_FLAG_AEAD_CIPHER \
                | EVP_CIPH_GCM_MODE)

static const EVP_CIPHER *ossltest_aes_128_gcm(void)
{
    if (_hidden_aes_128_gcm == NULL
        && ((_hidden_aes_128_gcm = VR_EVP_CIPHER_meth_new(NID_aes_128_gcm,
                                                       1 /* block size */,
                                                       16 /* key len */)) == NULL
            || !VR_EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_gcm,12)
            || !VR_EVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, AES_GCM_FLAGS)
            || !VR_EVP_CIPHER_meth_set_init(_hidden_aes_128_gcm,
                                         ossltest_aes128_gcm_init_key)
            || !VR_EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm,
                                              ossltest_aes128_gcm_cipher)
            || !VR_EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm,
                                              ossltest_aes128_gcm_ctrl)
            || !VR_EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm,
                              VR_EVP_CIPHER_impl_ctx_size(VR_EVP_aes_128_gcm())))) {
        VR_EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
        _hidden_aes_128_gcm = NULL;
    }
    return _hidden_aes_128_gcm;
}

static void destroy_ciphers(void)
{
    VR_EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
    VR_EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
    _hidden_aes_128_cbc = NULL;
}

static int bind_ossltest(ENGINE *e)
{
    /* Ensure the ossltest error handling is set up */
    ERR_load_OSSLTEST_strings();

    if (!VR_ENGINE_set_id(e, engine_ossltest_id)
        || !VR_ENGINE_set_name(e, engine_ossltest_name)
        || !VR_ENGINE_set_digests(e, ossltest_digests)
        || !VR_ENGINE_set_ciphers(e, ossltest_ciphers)
        || !VR_ENGINE_set_RAND(e, ossltest_rand_method())
        || !VR_ENGINE_set_destroy_function(e, ossltest_destroy)
        || !VR_ENGINE_set_init_function(e, ossltest_init)
        || !VR_ENGINE_set_finish_function(e, ossltest_finish)) {
        OSSLTESTerr(OSSLTEST_F_BIND_OSSLTEST, OSSLTEST_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_ossltest_id) != 0))
        return 0;
    if (!bind_ossltest(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

static ENGINE *engine_ossltest(void)
{
    ENGINE *ret = VR_ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_ossltest(ret)) {
        VR_ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_ossltest(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_ossltest();
    if (!toadd)
        return;
    VR_ENGINE_add(toadd);
    VR_ENGINE_free(toadd);
    VR_ERR_clear_error();
}


static int ossltest_init(ENGINE *e)
{
    return 1;
}


static int ossltest_finish(ENGINE *e)
{
    return 1;
}


static int ossltest_destroy(ENGINE *e)
{
    destroy_digests();
    destroy_ciphers();
    ERR_unload_OSSLTEST_strings();
    return 1;
}

static int ossltest_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        return ossltest_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_md5:
        *digest = digest_md5();
        break;
    case NID_sha1:
        *digest = digest_sha1();
        break;
    case NID_sha256:
        *digest = digest_sha256();
        break;
    case NID_sha384:
        *digest = digest_sha384();
        break;
    case NID_sha512:
        *digest = digest_sha512();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}

static int ossltest_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = ossltest_cipher_nids;
        return (sizeof(ossltest_cipher_nids) - 1)
               / sizeof(ossltest_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = ossltest_aes_128_cbc();
        break;
    case NID_aes_128_gcm:
        *cipher = ossltest_aes_128_gcm();
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}

static void fill_known_data(unsigned char *md, unsigned int len)
{
    unsigned int i;

    for (i=0; i<len; i++) {
        md[i] = (unsigned char)(i & 0xff);
    }
}

/*
 * VR_MD5 implementation. We go through the motions of doing VR_MD5 by deferring to
 * the standard implementation. Then we overwrite the result with a will defined
 * value, so that all "VR_MD5" digests using the test engine always end up with
 * the same value.
 */
#undef data
#define data(ctx) ((VR_MD5_CTX *)VR_EVP_MD_CTX_md_data(ctx))
static int digest_md5_init(EVP_MD_CTX *ctx)
{
    return VR_MD5_Init(data(ctx));
}

static int digest_md5_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count)
{
    return VR_MD5_Update(data(ctx), data, (size_t)count);
}

static int digest_md5_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = VR_MD5_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, VR_MD5_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * VR_SHA1 implementation.
 */
#undef data
#define data(ctx) ((SHA_CTX *)VR_EVP_MD_CTX_md_data(ctx))
static int digest_sha1_init(EVP_MD_CTX *ctx)
{
    return VR_SHA1_Init(data(ctx));
}

static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                              size_t count)
{
    return VR_SHA1_Update(data(ctx), data, (size_t)count);
}

static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = VR_SHA1_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, SHA_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * VR_SHA256 implementation.
 */
#undef data
#define data(ctx) ((VR_SHA256_CTX *)VR_EVP_MD_CTX_md_data(ctx))
static int digest_sha256_init(EVP_MD_CTX *ctx)
{
    return VR_SHA256_Init(data(ctx));
}

static int digest_sha256_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    return VR_SHA256_Update(data(ctx), data, (size_t)count);
}

static int digest_sha256_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = VR_SHA256_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, VR_SHA256_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * VR_SHA384/512 implementation.
 */
#undef data
#define data(ctx) ((VR_SHA512_CTX *)VR_EVP_MD_CTX_md_data(ctx))
static int digest_sha384_init(EVP_MD_CTX *ctx)
{
    return VR_SHA384_Init(data(ctx));
}

static int digest_sha512_init(EVP_MD_CTX *ctx)
{
    return VR_SHA512_Init(data(ctx));
}

static int digest_sha512_update(EVP_MD_CTX *ctx, const void *data,
                                size_t count)
{
    return VR_SHA512_Update(data(ctx), data, (size_t)count);
}

static int digest_sha384_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    /* Actually uses VR_SHA512_Final! */
    ret = VR_SHA512_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, VR_SHA384_DIGEST_LENGTH);
    }
    return ret;
}

static int digest_sha512_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int ret;
    ret = VR_SHA512_Final(md, data(ctx));

    if (ret > 0) {
        fill_known_data(md, VR_SHA512_DIGEST_LENGTH);
    }
    return ret;
}

/*
 * AES128 Implementation
 */

int ossltest_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    return VR_EVP_CIPHER_meth_get_init(VR_EVP_aes_128_cbc()) (ctx, key, iv, enc);
}

int ossltest_aes128_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    unsigned char *tmpbuf;
    int ret;

    tmpbuf = OPENSSL_malloc(inl);

    /* OPENSSL_malloc will return NULL if inl == 0 */
    if (tmpbuf == NULL && inl > 0)
        return -1;

    /* Remember what we were asked to encrypt */
    if (tmpbuf != NULL)
        memcpy(tmpbuf, in, inl);

    /* Go through the motions of encrypting it */
    ret = VR_EVP_CIPHER_meth_get_do_cipher(VR_EVP_aes_128_cbc())(ctx, out, in, inl);

    /* Throw it all away and just use the plaintext as the output */
    if (tmpbuf != NULL)
        memcpy(out, tmpbuf, inl);
    VR_OPENSSL_free(tmpbuf);

    return ret;
}

int ossltest_aes128_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    return VR_EVP_CIPHER_meth_get_init(VR_EVP_aes_128_gcm()) (ctx, key, iv, enc);
}


int ossltest_aes128_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    unsigned char *tmpbuf = OPENSSL_malloc(inl);

    /* OPENSSL_malloc will return NULL if inl == 0 */
    if (tmpbuf == NULL && inl > 0)
        return -1;

    /* Remember what we were asked to encrypt */
    if (tmpbuf != NULL)
        memcpy(tmpbuf, in, inl);

    /* Go through the motions of encrypting it */
    VR_EVP_CIPHER_meth_get_do_cipher(VR_EVP_aes_128_gcm())(ctx, out, in, inl);

    /* Throw it all away and just use the plaintext as the output */
    if (tmpbuf != NULL && out != NULL)
        memcpy(out, tmpbuf, inl);
    VR_OPENSSL_free(tmpbuf);

    return inl;
}

static int ossltest_aes128_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr)
{
    /* Pass the ctrl down */
    int ret = VR_EVP_CIPHER_meth_get_ctrl(VR_EVP_aes_128_gcm())(ctx, type, arg, ptr);

    if (ret <= 0)
        return ret;

    switch(type) {
    case EVP_CTRL_AEAD_GET_TAG:
        /* Always give the same tag */
        memset(ptr, 0, EVP_GCM_TLS_TAG_LEN);
        break;

    default:
        break;
    }

    return 1;
}

static int ossltest_rand_bytes(unsigned char *buf, int num)
{
    unsigned char val = 1;

    while (--num >= 0)
        *buf++ = val++;
    return 1;
}

static int ossltest_rand_status(void)
{
    return 1;
}

static const RAND_METHOD *ossltest_rand_method(void)
{

    static RAND_METHOD osslt_rand_meth = {
        NULL,
        ossltest_rand_bytes,
        NULL,
        NULL,
        ossltest_rand_bytes,
        ossltest_rand_status
    };

    return &osslt_rand_meth;
}
