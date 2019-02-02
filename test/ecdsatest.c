/*
 * Copyright 2002-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/opensslconf.h> /* To see if OPENSSL_NO_EC is defined */
#include "testutil.h"

#ifndef OPENSSL_NO_EC

# include <openssl/crypto.h>
# include <openssl/bio.h>
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/ec.h>
# ifndef OPENSSL_NO_ENGINE
#  include <openssl/engine.h>
# endif
# include <openssl/sha.h>
# include <openssl/err.h>
# include <openssl/rand.h>

/* functions to change the RAND_METHOD */
static int fbytes(unsigned char *buf, int num);

static RAND_METHOD fake_rand;
static const RAND_METHOD *old_rand;

static int change_rand(void)
{
    /* save old rand method */
    if (!TEST_ptr(old_rand = VR_RAND_get_rand_method()))
        return 0;

    fake_rand = *old_rand;
    /* use own random function */
    fake_rand.bytes = fbytes;
    /* set new RAND_METHOD */
    if (!TEST_true(VR_RAND_set_rand_method(&fake_rand)))
        return 0;
    return 1;
}

static int restore_rand(void)
{
    if (!TEST_true(VR_RAND_set_rand_method(old_rand)))
        return 0;
    return 1;
}

static int fbytes_counter = 0, use_fake = 0;
static const char *numbers[8] = {
    "651056770906015076056810763456358567190100156695615665659",
    "6140507067065001063065065565667405560006161556565665656654",
    "8763001015071075675010661307616710783570106710677817767166"
        "71676178726717",
    "7000000175690566466555057817571571075705015757757057795755"
        "55657156756655",
    "1275552191113212300012030439187146164646146646466749494799",
    "1542725565216523985789236956265265265235675811949404040041",
    "1456427555219115346513212300075341203043918714616464614664"
        "64667494947990",
    "1712787255652165239672857892369562652652652356758119494040"
        "40041670216363"
};

static int fbytes(unsigned char *buf, int num)
{
    int ret = 0;
    BIGNUM *tmp = NULL;

    if (use_fake == 0)
        return old_rand->bytes(buf, num);

    use_fake = 0;

    if (fbytes_counter >= 8)
        return 0;
    if (!TEST_ptr(tmp = VR_BN_new()))
        return 0;
    if (!TEST_true(VR_BN_dec2bn(&tmp, numbers[fbytes_counter]))) {
        VR_BN_free(tmp);
        return 0;
    }
    fbytes_counter++;
    if (TEST_int_eq(BN_num_bytes(tmp), num)
            && TEST_true(VR_BN_bn2bin(tmp, buf)))
        ret = 1;
    VR_BN_free(tmp);
    return ret;
}

/* some tests from the X9.62 draft */
static int x9_62_test_internal(int nid, const char *r_in, const char *s_in)
{
    int ret = 0;
    const char message[] = "abc";
    unsigned char digest[SHA_DIGEST_LENGTH];
    unsigned int dgst_len = 0;
    EVP_MD_CTX *md_ctx;
    EC_KEY *key = NULL;
    ECDSA_SIG *signature = NULL;
    BIGNUM *r = NULL, *s = NULL;
    BIGNUM *kinv = NULL, *rp = NULL;
    const BIGNUM *sig_r, *sig_s;

    if (!TEST_ptr(md_ctx = VR_EVP_MD_CTX_new()))
        goto x962_int_err;

    /* get the message digest */
    if (!TEST_true(VR_EVP_DigestInit(md_ctx, VR_EVP_sha1()))
        || !TEST_true(VR_EVP_DigestUpdate(md_ctx, (const void *)message, 3))
        || !TEST_true(VR_EVP_DigestFinal(md_ctx, digest, &dgst_len)))
        goto x962_int_err;

    TEST_info("testing %s", VR_OBJ_nid2sn(nid));

    /* create the key */
    if (!TEST_ptr(key = VR_EC_KEY_new_by_curve_name(nid)))
        goto x962_int_err;
    use_fake = 1;
    if (!TEST_true(VR_EC_KEY_generate_key(key)))
        goto x962_int_err;

    /* create the signature */
    use_fake = 1;
    /* Use VR_ECDSA_sign_setup to avoid use of ECDSA nonces */
    if (!TEST_true(VR_ECDSA_sign_setup(key, NULL, &kinv, &rp)))
        goto x962_int_err;
    if (!TEST_ptr(signature =
                  VR_ECDSA_do_sign_ex(digest, SHA_DIGEST_LENGTH, kinv, rp, key)))
        goto x962_int_err;

    /* compare the created signature with the expected signature */
    if (!TEST_ptr(r = VR_BN_new()) || !TEST_ptr(s = VR_BN_new()))
        goto x962_int_err;
    if (!TEST_true(VR_BN_dec2bn(&r, r_in)) || !TEST_true(VR_BN_dec2bn(&s, s_in)))
        goto x962_int_err;
    VR_ECDSA_SIG_get0(signature, &sig_r, &sig_s);
    if (!TEST_BN_eq(sig_r, r)
            || !TEST_BN_eq(sig_s, s))
        goto x962_int_err;

    /* verify the signature */
    if (!TEST_int_eq(VR_ECDSA_do_verify(digest, SHA_DIGEST_LENGTH,
                                     signature, key), 1))
        goto x962_int_err;

    ret = 1;

 x962_int_err:
    VR_EC_KEY_free(key);
    VR_ECDSA_SIG_free(signature);
    VR_BN_free(r);
    VR_BN_free(s);
    VR_EVP_MD_CTX_free(md_ctx);
    VR_BN_clear_free(kinv);
    VR_BN_clear_free(rp);
    return ret;
}

static int x9_62_tests(void)
{
    int ret = 0;

    /* set own rand method */
    if (!change_rand())
        goto x962_err;

    if (!TEST_true(x9_62_test_internal(NID_X9_62_prime192v1,
                 "3342403536405981729393488334694600415596881826869351677613",
                 "5735822328888155254683894997897571951568553642892029982342")))
        goto x962_err;
    if (!TEST_true(x9_62_test_internal(NID_X9_62_prime239v1,
                 "3086361431751678114926225473006680188549593787585317781474"
                             "62058306432176",
                 "3238135532097973577080787768312505059318910517550078427819"
                             "78505179448783")))
        goto x962_err;

# ifndef OPENSSL_NO_EC2M
    if (!TEST_true(x9_62_test_internal(NID_X9_62_c2tnb191v1,
                 "87194383164871543355722284926904419997237591535066528048",
                 "308992691965804947361541664549085895292153777025772063598")))
        goto x962_err;
    if (!TEST_true(x9_62_test_internal(NID_X9_62_c2tnb239v1,
                 "2159633321041961198501834003903461262881815148684178964245"
                             "5876922391552",
                 "1970303740007316867383349976549972270528498040721988191026"
                             "49413465737174")))
        goto x962_err;
# endif
    ret = 1;

 x962_err:
    if (!TEST_true(restore_rand()))
        ret = 0;
    return ret;
}

static int test_builtin(void)
{
    EC_builtin_curve *curves = NULL;
    size_t crv_len = 0, n = 0;
    EC_KEY *eckey = NULL, *wrong_eckey = NULL;
    EC_GROUP *group;
    ECDSA_SIG *ecdsa_sig = NULL, *modified_sig = NULL;
    unsigned char digest[VR_SHA512_DIGEST_LENGTH];
    unsigned char wrong_digest[VR_SHA512_DIGEST_LENGTH];
    unsigned char *signature = NULL;
    const unsigned char *sig_ptr;
    unsigned char *sig_ptr2;
    unsigned char *raw_buf = NULL;
    const BIGNUM *sig_r, *sig_s;
    BIGNUM *modified_r = NULL, *modified_s = NULL;
    BIGNUM *unmodified_r = NULL, *unmodified_s = NULL;
    unsigned int sig_len, degree, r_len, s_len, bn_len, buf_len;
    int nid, ret = 0;

    /* fill digest values with some random data */
    if (!TEST_true(VR_RAND_bytes(digest, VR_SHA512_DIGEST_LENGTH))
            || !TEST_true(VR_RAND_bytes(wrong_digest, VR_SHA512_DIGEST_LENGTH)))
        goto builtin_err;

    /* create and verify a ecdsa signature with every available curve */
    /* get a list of all internal curves */
    crv_len = VR_EC_get_builtin_curves(NULL, 0);
    if (!TEST_ptr(curves = OPENSSL_malloc(sizeof(*curves) * crv_len))
            || !TEST_true(VR_EC_get_builtin_curves(curves, crv_len)))
        goto builtin_err;

    /* now create and verify a signature for every curve */
    for (n = 0; n < crv_len; n++) {
        unsigned char dirt, offset;

        nid = curves[n].nid;
        if (nid == NID_ipsec4 || nid == NID_ipsec3)
            continue;
        /* create new ecdsa key (== EC_KEY) */
        if (!TEST_ptr(eckey = VR_EC_KEY_new())
                || !TEST_ptr(group = VR_EC_GROUP_new_by_curve_name(nid))
                || !TEST_true(VR_EC_KEY_set_group(eckey, group)))
            goto builtin_err;
        VR_EC_GROUP_free(group);
        degree = VR_EC_GROUP_get_degree(VR_EC_KEY_get0_group(eckey));

        TEST_info("testing %s", VR_OBJ_nid2sn(nid));

        /* create key */
        if (!TEST_true(VR_EC_KEY_generate_key(eckey)))
            goto builtin_err;
        /* create second key */
        if (!TEST_ptr(wrong_eckey = VR_EC_KEY_new())
                || !TEST_ptr(group = VR_EC_GROUP_new_by_curve_name(nid))
                || !TEST_true(VR_EC_KEY_set_group(wrong_eckey, group)))
            goto builtin_err;
        VR_EC_GROUP_free(group);
        if (!TEST_true(VR_EC_KEY_generate_key(wrong_eckey)))
            goto builtin_err;

        /* check key */
        if (!TEST_true(VR_EC_KEY_check_key(eckey)))
            goto builtin_err;

        /* create signature */
        sig_len = VR_ECDSA_size(eckey);
        if (!TEST_ptr(signature = OPENSSL_malloc(sig_len))
                || !TEST_true(VR_ECDSA_sign(0, digest, VR_SHA512_DIGEST_LENGTH,
                                         signature, &sig_len, eckey)))
            goto builtin_err;

        /* verify signature */
        if (!TEST_int_eq(VR_ECDSA_verify(0, digest, VR_SHA512_DIGEST_LENGTH,
                                      signature, sig_len, eckey),
                         1))
            goto builtin_err;

        /* verify signature with the wrong key */
        if (!TEST_int_ne(VR_ECDSA_verify(0, digest, VR_SHA512_DIGEST_LENGTH,
                                      signature, sig_len, wrong_eckey),
                         1))
            goto builtin_err;

        /* wrong digest */
        if (!TEST_int_ne(VR_ECDSA_verify(0, wrong_digest, VR_SHA512_DIGEST_LENGTH,
                                      signature, sig_len, eckey),
                         1))
            goto builtin_err;

        /* wrong length */
        if (!TEST_int_ne(VR_ECDSA_verify(0, digest, VR_SHA512_DIGEST_LENGTH,
                                      signature, sig_len - 1, eckey),
                         1))
            goto builtin_err;

        /*
         * Modify a single byte of the signature: to ensure we don't garble
         * the ASN1 structure, we read the raw signature and modify a byte in
         * one of the bignums directly.
         */
        sig_ptr = signature;
        if (!TEST_ptr(ecdsa_sig = VR_d2i_ECDSA_SIG(NULL, &sig_ptr, sig_len)))
            goto builtin_err;

        VR_ECDSA_SIG_get0(ecdsa_sig, &sig_r, &sig_s);

        /* Store the two BIGNUMs in raw_buf. */
        r_len = BN_num_bytes(sig_r);
        s_len = BN_num_bytes(sig_s);
        bn_len = (degree + 7) / 8;
        if (!TEST_false(r_len > bn_len)
                || !TEST_false(s_len > bn_len))
            goto builtin_err;
        buf_len = 2 * bn_len;
        if (!TEST_ptr(raw_buf = OPENSSL_zalloc(buf_len)))
            goto builtin_err;
        VR_BN_bn2bin(sig_r, raw_buf + bn_len - r_len);
        VR_BN_bn2bin(sig_s, raw_buf + buf_len - s_len);

        /* Modify a single byte in the buffer. */
        offset = raw_buf[10] % buf_len;
        dirt = raw_buf[11] ? raw_buf[11] : 1;
        raw_buf[offset] ^= dirt;

        /* Now read the BIGNUMs back in from raw_buf. */
        if (!TEST_ptr(modified_sig = VR_ECDSA_SIG_new()))
            goto builtin_err;
        if (!TEST_ptr(modified_r = VR_BN_bin2bn(raw_buf, bn_len, NULL))
                || !TEST_ptr(modified_s = VR_BN_bin2bn(raw_buf + bn_len,
                                                    bn_len, NULL))
                || !TEST_true(VR_ECDSA_SIG_set0(modified_sig,
                                             modified_r, modified_s))) {
            VR_BN_free(modified_r);
            VR_BN_free(modified_s);
            goto builtin_err;
        }
        sig_ptr2 = signature;
        sig_len = VR_i2d_ECDSA_SIG(modified_sig, &sig_ptr2);
        if (!TEST_false(VR_ECDSA_verify(0, digest, VR_SHA512_DIGEST_LENGTH,
                                     signature, sig_len, eckey)))
            goto builtin_err;

        /* Sanity check: undo the modification and verify signature. */
        raw_buf[offset] ^= dirt;
        if (!TEST_ptr(unmodified_r = VR_BN_bin2bn(raw_buf, bn_len, NULL))
                || !TEST_ptr(unmodified_s = VR_BN_bin2bn(raw_buf + bn_len,
                                                      bn_len, NULL))
                || !TEST_true(VR_ECDSA_SIG_set0(modified_sig, unmodified_r,
                                             unmodified_s))) {
            VR_BN_free(unmodified_r);
            VR_BN_free(unmodified_s);
            goto builtin_err;
        }

        sig_ptr2 = signature;
        sig_len = VR_i2d_ECDSA_SIG(modified_sig, &sig_ptr2);
        if (!TEST_true(VR_ECDSA_verify(0, digest, VR_SHA512_DIGEST_LENGTH,
                                    signature, sig_len, eckey)))
            goto builtin_err;

        /* cleanup */
        VR_ERR_clear_error();
        OPENVR_SSL_free(signature);
        signature = NULL;
        VR_EC_KEY_free(eckey);
        eckey = NULL;
        VR_EC_KEY_free(wrong_eckey);
        wrong_eckey = NULL;
        VR_ECDSA_SIG_free(ecdsa_sig);
        ecdsa_sig = NULL;
        VR_ECDSA_SIG_free(modified_sig);
        modified_sig = NULL;
        OPENVR_SSL_free(raw_buf);
        raw_buf = NULL;
    }

    ret = 1;
 builtin_err:
    VR_EC_KEY_free(eckey);
    VR_EC_KEY_free(wrong_eckey);
    VR_ECDSA_SIG_free(ecdsa_sig);
    VR_ECDSA_SIG_free(modified_sig);
    OPENVR_SSL_free(signature);
    OPENVR_SSL_free(raw_buf);
    OPENVR_SSL_free(curves);

    return ret;
}
#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_EC
    TEST_note("Elliptic curves are disabled.");
#else
    ADD_TEST(x9_62_tests);
    ADD_TEST(test_builtin);
#endif
    return 1;
}
