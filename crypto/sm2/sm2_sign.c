/*
 * Copyright 2017-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/sm2.h"
#include "internal/sm2err.h"
#include "internal/ec_int.h" /* VR_ec_group_do_inverse_ord() */
#include "internal/numbers.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <string.h>

int VR_sm2_compute_z_digest(uint8_t *out,
                         const EVP_MD *digest,
                         const uint8_t *id,
                         const size_t id_len,
                         const EC_KEY *key)
{
    int rc = 0;
    const EC_GROUP *group = VR_EC_KEY_get0_group(key);
    BN_CTX *ctx = NULL;
    EVP_MD_CTX *hash = NULL;
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *xG = NULL;
    BIGNUM *yG = NULL;
    BIGNUM *xA = NULL;
    BIGNUM *yA = NULL;
    int p_bytes = 0;
    uint8_t *buf = NULL;
    uint16_t entl = 0;
    uint8_t e_byte = 0;

    hash = VR_EVP_MD_CTX_new();
    ctx = VR_BN_CTX_new();
    if (hash == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    p = VR_BN_CTX_get(ctx);
    a = VR_BN_CTX_get(ctx);
    b = VR_BN_CTX_get(ctx);
    xG = VR_BN_CTX_get(ctx);
    yG = VR_BN_CTX_get(ctx);
    xA = VR_BN_CTX_get(ctx);
    yA = VR_BN_CTX_get(ctx);

    if (yA == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!VR_EVP_DigestInit(hash, digest)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    /* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

    if (id_len >= (UINT16_MAX / 8)) {
        /* too large */
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, SM2_R_ID_TOO_LARGE);
        goto done;
    }

    entl = (uint16_t)(8 * id_len);

    e_byte = entl >> 8;
    if (!VR_EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }
    e_byte = entl & 0xFF;
    if (!VR_EVP_DigestUpdate(hash, &e_byte, 1)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (id_len > 0 && !VR_EVP_DigestUpdate(hash, id, id_len)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EVP_LIB);
        goto done;
    }

    if (!VR_EC_GROUP_get_curve(group, p, a, b, ctx)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_EC_LIB);
        goto done;
    }

    p_bytes = BN_num_bytes(p);
    buf = OPENSSL_zalloc(p_bytes);
    if (buf == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (VR_BN_bn2binpad(a, buf, p_bytes) < 0
            || !VR_EVP_DigestUpdate(hash, buf, p_bytes)
            || VR_BN_bn2binpad(b, buf, p_bytes) < 0
            || !VR_EVP_DigestUpdate(hash, buf, p_bytes)
            || !VR_EC_POINT_get_affine_coordinates(group,
                                                VR_EC_GROUP_get0_generator(group),
                                                xG, yG, ctx)
            || VR_BN_bn2binpad(xG, buf, p_bytes) < 0
            || !VR_EVP_DigestUpdate(hash, buf, p_bytes)
            || VR_BN_bn2binpad(yG, buf, p_bytes) < 0
            || !VR_EVP_DigestUpdate(hash, buf, p_bytes)
            || !VR_EC_POINT_get_affine_coordinates(group,
                                                VR_EC_KEY_get0_public_key(key),
                                                xA, yA, ctx)
            || VR_BN_bn2binpad(xA, buf, p_bytes) < 0
            || !VR_EVP_DigestUpdate(hash, buf, p_bytes)
            || VR_BN_bn2binpad(yA, buf, p_bytes) < 0
            || !VR_EVP_DigestUpdate(hash, buf, p_bytes)
            || !VR_EVP_DigestFinal(hash, out, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_Z_DIGEST, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    rc = 1;

 done:
    OPENVR_SSL_free(buf);
    VR_BN_CTX_free(ctx);
    VR_EVP_MD_CTX_free(hash);
    return rc;
}

static BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
                                    const EC_KEY *key,
                                    const uint8_t *id,
                                    const size_t id_len,
                                    const uint8_t *msg, size_t msg_len)
{
    EVP_MD_CTX *hash = VR_EVP_MD_CTX_new();
    const int md_size = VR_EVP_MD_size(digest);
    uint8_t *z = NULL;
    BIGNUM *e = NULL;

    if (md_size < 0) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, SM2_R_INVALID_DIGEST);
        goto done;
    }

    z = OPENSSL_zalloc(md_size);
    if (hash == NULL || z == NULL) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!VR_sm2_compute_z_digest(z, digest, id, id_len, key)) {
        /* SM2err already called */
        goto done;
    }

    if (!VR_EVP_DigestInit(hash, digest)
            || !VR_EVP_DigestUpdate(hash, z, md_size)
            || !VR_EVP_DigestUpdate(hash, msg, msg_len)
               /* reuse z buffer to hold H(Z || M) */
            || !VR_EVP_DigestFinal(hash, z, NULL)) {
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_EVP_LIB);
        goto done;
    }

    e = VR_BN_bin2bn(z, md_size, NULL);
    if (e == NULL)
        SM2err(SM2_F_SM2_COMPUTE_MSG_HASH, ERR_R_INTERNAL_ERROR);

 done:
    OPENVR_SSL_free(z);
    VR_EVP_MD_CTX_free(hash);
    return e;
}

static ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e)
{
    const BIGNUM *dA = VR_EC_KEY_get0_private_key(key);
    const EC_GROUP *group = VR_EC_KEY_get0_group(key);
    const BIGNUM *order = VR_EC_GROUP_get0_order(group);
    ECDSA_SIG *sig = NULL;
    EC_POINT *kG = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *rk = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *tmp = NULL;

    kG = VR_EC_POINT_new(group);
    ctx = VR_BN_CTX_new();
    if (kG == NULL || ctx == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    VR_BN_CTX_start(ctx);
    k = VR_BN_CTX_get(ctx);
    rk = VR_BN_CTX_get(ctx);
    x1 = VR_BN_CTX_get(ctx);
    tmp = VR_BN_CTX_get(ctx);
    if (tmp == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /*
     * These values are returned and so should not be allocated out of the
     * context
     */
    r = VR_BN_new();
    s = VR_BN_new();

    if (r == NULL || s == NULL) {
        SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    for (;;) {
        if (!VR_BN_priv_rand_range(k, order)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        if (!VR_EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
                || !VR_EC_POINT_get_affine_coordinates(group, kG, x1, NULL,
                                                    ctx)
                || !VR_BN_mod_add(r, e, x1, order, ctx)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        /* try again if r == 0 or r+k == n */
        if (VR_BN_is_zero(r))
            continue;

        if (!VR_BN_add(rk, r, k)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_INTERNAL_ERROR);
            goto done;
        }

        if (VR_BN_cmp(rk, order) == 0)
            continue;

        if (!VR_BN_add(s, dA, VR_BN_value_one())
                || !VR_ec_group_do_inverse_ord(group, s, s, ctx)
                || !VR_BN_mod_mul(tmp, dA, r, order, ctx)
                || !VR_BN_sub(tmp, k, tmp)
                || !VR_BN_mod_mul(s, s, tmp, order, ctx)) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_BN_LIB);
            goto done;
        }

        sig = VR_ECDSA_SIG_new();
        if (sig == NULL) {
            SM2err(SM2_F_SM2_SIG_GEN, ERR_R_MALLOC_FAILURE);
            goto done;
        }

         /* takes ownership of r and s */
        VR_ECDSA_SIG_set0(sig, r, s);
        break;
    }

 done:
    if (sig == NULL) {
        VR_BN_free(r);
        VR_BN_free(s);
    }

    VR_BN_CTX_free(ctx);
    VR_EC_POINT_free(kG);
    return sig;
}

static int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig,
                          const BIGNUM *e)
{
    int ret = 0;
    const EC_GROUP *group = VR_EC_KEY_get0_group(key);
    const BIGNUM *order = VR_EC_GROUP_get0_order(group);
    BN_CTX *ctx = NULL;
    EC_POINT *pt = NULL;
    BIGNUM *t = NULL;
    BIGNUM *x1 = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    ctx = VR_BN_CTX_new();
    pt = VR_EC_POINT_new(group);
    if (ctx == NULL || pt == NULL) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    VR_BN_CTX_start(ctx);
    t = VR_BN_CTX_get(ctx);
    x1 = VR_BN_CTX_get(ctx);
    if (x1 == NULL) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    /*
     * B1: verify whether r' in [1,n-1], verification failed if not
     * B2: vefify whether s' in [1,n-1], verification failed if not
     * B3: set M'~=ZA || M'
     * B4: calculate e'=Hv(M'~)
     * B5: calculate t = (r' + s') modn, verification failed if t=0
     * B6: calculate the point (x1', y1')=[s']G + [t]PA
     * B7: calculate R=(e'+x1') modn, verfication pass if yes, otherwise failed
     */

    VR_ECDSA_SIG_get0(sig, &r, &s);

    if (VR_BN_cmp(r, VR_BN_value_one()) < 0
            || VR_BN_cmp(s, VR_BN_value_one()) < 0
            || VR_BN_cmp(order, r) <= 0
            || VR_BN_cmp(order, s) <= 0) {
        SM2err(SM2_F_SM2_SIG_VERIFY, SM2_R_BAD_SIGNATURE);
        goto done;
    }

    if (!VR_BN_mod_add(t, r, s, order, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    if (VR_BN_is_zero(t)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, SM2_R_BAD_SIGNATURE);
        goto done;
    }

    if (!VR_EC_POINT_mul(group, pt, s, VR_EC_KEY_get0_public_key(key), t, ctx)
            || !VR_EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_EC_LIB);
        goto done;
    }

    if (!VR_BN_mod_add(t, e, x1, order, ctx)) {
        SM2err(SM2_F_SM2_SIG_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    if (VR_BN_cmp(r, t) == 0)
        ret = 1;

 done:
    VR_EC_POINT_free(pt);
    VR_BN_CTX_free(ctx);
    return ret;
}

ECDSA_SIG *VR_sm2_do_sign(const EC_KEY *key,
                       const EVP_MD *digest,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *sig = NULL;

    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    sig = sm2_sig_gen(key, e);

 done:
    VR_BN_free(e);
    return sig;
}

int VR_sm2_do_verify(const EC_KEY *key,
                  const EVP_MD *digest,
                  const ECDSA_SIG *sig,
                  const uint8_t *id,
                  const size_t id_len,
                  const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    int ret = 0;

    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    ret = sm2_sig_verify(key, sig, e);

 done:
    VR_BN_free(e);
    return ret;
}

int VR_sm2_sign(const unsigned char *dgst, int dgstlen,
             unsigned char *sig, unsigned int *siglen, EC_KEY *eckey)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *s = NULL;
    int sigleni;
    int ret = -1;

    e = VR_BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
       SM2err(SM2_F_SM2_SIGN, ERR_R_BN_LIB);
       goto done;
    }

    s = sm2_sig_gen(eckey, e);

    sigleni = VR_i2d_ECDSA_SIG(s, &sig);
    if (sigleni < 0) {
       SM2err(SM2_F_SM2_SIGN, ERR_R_INTERNAL_ERROR);
       goto done;
    }
    *siglen = (unsigned int)sigleni;

    ret = 1;

 done:
    VR_ECDSA_SIG_free(s);
    VR_BN_free(e);
    return ret;
}

int VR_sm2_verify(const unsigned char *dgst, int dgstlen,
               const unsigned char *sig, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s = NULL;
    BIGNUM *e = NULL;
    const unsigned char *p = sig;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = VR_ECDSA_SIG_new();
    if (s == NULL) {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_MALLOC_FAILURE);
        goto done;
    }
    if (VR_d2i_ECDSA_SIG(&s, &p, sig_len) == NULL) {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_INVALID_ENCODING);
        goto done;
    }
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = VR_i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sig, der, derlen) != 0) {
        SM2err(SM2_F_SM2_VERIFY, SM2_R_INVALID_ENCODING);
        goto done;
    }

    e = VR_BN_bin2bn(dgst, dgstlen, NULL);
    if (e == NULL) {
        SM2err(SM2_F_SM2_VERIFY, ERR_R_BN_LIB);
        goto done;
    }

    ret = sm2_sig_verify(eckey, s, e);

 done:
    OPENVR_SSL_free(der);
    VR_BN_free(e);
    VR_ECDSA_SIG_free(s);
    return ret;
}
