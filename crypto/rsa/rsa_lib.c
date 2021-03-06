/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include "internal/bn_int.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "internal/evp_int.h"
#include "rsa_locl.h"

RSA *VR_RSA_new(void)
{
    return VR_RSA_new_method(NULL);
}

const RSA_METHOD *VR_RSA_get_method(const RSA *rsa)
{
    return rsa->meth;
}

int VR_RSA_set_method(RSA *rsa, const RSA_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const RSA_METHOD *mtmp;
    mtmp = rsa->meth;
    if (mtmp->finish)
        mtmp->finish(rsa);
#ifndef OPENSSL_NO_ENGINE
    VR_ENGINE_finish(rsa->engine);
    rsa->engine = NULL;
#endif
    rsa->meth = meth;
    if (meth->init)
        meth->init(rsa);
    return 1;
}

RSA *VR_RSA_new_method(ENGINE *engine)
{
    RSA *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = VR_CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        VR_OPENSSL_free(ret);
        return NULL;
    }

    ret->meth = VR_RSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    if (engine) {
        if (!VR_ENGINE_init(engine)) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
        ret->engine = engine;
    } else {
        ret->engine = VR_ENGINE_get_default_RSA();
    }
    if (ret->engine) {
        ret->meth = VR_ENGINE_get_RSA(ret->engine);
        if (ret->meth == NULL) {
            RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
    }
#endif

    ret->flags = ret->meth->flags & ~RSA_FLAG_NON_FIPS_ALLOW;
    if (!VR_CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, ret, &ret->ex_data)) {
        goto err;
    }

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        RSAerr(RSA_F_RSA_NEW_METHOD, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

 err:
    VR_RSA_free(ret);
    return NULL;
}

void VR_RSA_free(RSA *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("RSA", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    VR_ENGINE_finish(r->engine);
#endif

    VR_CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, r, &r->ex_data);

    VR_CRYPTO_THREAD_lock_free(r->lock);

    VR_BN_free(r->n);
    VR_BN_free(r->e);
    VR_BN_clear_free(r->d);
    VR_BN_clear_free(r->p);
    VR_BN_clear_free(r->q);
    VR_BN_clear_free(r->dmp1);
    VR_BN_clear_free(r->dmq1);
    VR_BN_clear_free(r->iqmp);
    VR_RSA_PSS_PARAMS_free(r->pss);
    sk_VR_RSA_PRIME_INFO_pop_free(r->prime_infos, VR_rsa_multip_info_free);
    VR_BN_BLINDING_free(r->blinding);
    VR_BN_BLINDING_free(r->mt_blinding);
    VR_OPENSSL_free(r->bignum_data);
    VR_OPENSSL_free(r);
}

int VR_RSA_up_ref(RSA *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("RSA", r);
    REF_ASSERT_ISNT(i < 2);
    return i > 1 ? 1 : 0;
}

int VR_RSA_set_ex_data(RSA *r, int idx, void *arg)
{
    return VR_CRYPTO_set_ex_data(&r->ex_data, idx, arg);
}

void *VR_RSA_get_ex_data(const RSA *r, int idx)
{
    return VR_CRYPTO_get_ex_data(&r->ex_data, idx);
}

/*
 * Define a scaling constant for our fixed point arithmetic.
 * This value must be a power of two because the base two logarithm code
 * makes this assumption.  The exponent must also be a multiple of three so
 * that the scale factor has an exact cube root.  Finally, the scale factor
 * should not be so large that a multiplication of two scaled numbers
 * overflows a 64 bit unsigned integer.
 */
static const unsigned int scale = 1 << 18;
static const unsigned int cbrt_scale = 1 << (2 * 18 / 3);

/* Define some constants, none exceed 32 bits */
static const unsigned int log_2  = 0x02c5c8;    /* scale * log(2) */
static const unsigned int log_e  = 0x05c551;    /* scale * log2(M_E) */
static const unsigned int c1_923 = 0x07b126;    /* scale * 1.923 */
static const unsigned int c4_690 = 0x12c28f;    /* scale * 4.690 */

/*
 * Multiply two scale integers together and rescale the result.
 */
static ossl_inline uint64_t mul2(uint64_t a, uint64_t b)
{
    return a * b / scale;
}

/*
 * Calculate the cube root of a 64 bit scaled integer.
 * Although the cube root of a 64 bit number does fit into a 32 bit unsigned
 * integer, this is not guaranteed after scaling, so this function has a
 * 64 bit return.  This uses the shifting nth root algorithm with some
 * algebraic simplifications.
 */
static uint64_t icbrt64(uint64_t x)
{
    uint64_t r = 0;
    uint64_t b;
    int s;

    for (s = 63; s >= 0; s -= 3) {
        r <<= 1;
        b = 3 * r * (r + 1) + 1;
        if ((x >> s) >= b) {
            x -= b << s;
            r++;
        }
    }
    return r * cbrt_scale;
}

/*
 * Calculate the natural logarithm of a 64 bit scaled integer.
 * This is done by calculating a base two logarithm and scaling.
 * The maximum logarithm (base 2) is 64 and this reduces base e, so
 * a 32 bit result should not overflow.  The argument passed must be
 * greater than unity so we don't need to handle negative results.
 */
static uint32_t ilog_e(uint64_t v)
{
    uint32_t i, r = 0;

    /*
     * Scale down the value into the range 1 .. 2.
     *
     * If fractional numbers need to be processed, another loop needs
     * to go here that checks v < scale and if so multiplies it by 2 and
     * reduces r by scale.  This also means making r signed.
     */
    while (v >= 2 * scale) {
        v >>= 1;
        r += scale;
    }
    for (i = scale / 2; i != 0; i /= 2) {
        v = mul2(v, v);
        if (v >= 2 * scale) {
            v >>= 1;
            r += i;
        }
    }
    r = (r * (uint64_t)scale) / log_e;
    return r;
}

/*
 * NIST SP 800-56B rev 2 Appendix D: Maximum Security Strength Estimates for IFC
 * Modulus Lengths.
 *
 * E = \frac{1.923 \sqrt[3]{nBits \cdot log_e(2)}
 *           \cdot(log_e(nBits \cdot log_e(2))^{2/3} - 4.69}{log_e(2)}
 * The two cube roots are merged together here.
 */
static uint16_t rsa_compute_security_bits(int n)
{
    uint64_t x;
    uint32_t lx;
    uint16_t y;

    /* Look for common values as listed in SP 800-56B rev 2 Appendix D */
    switch (n) {
    case 2048:
        return 112;
    case 3072:
        return 128;
    case 4096:
        return 152;
    case 6144:
        return 176;
    case 8192:
        return 200;
    }
    /*
     * The first incorrect result (i.e. not accurate or off by one low) occurs
     * for n = 699668.  The true value here is 1200.  Instead of using this n
     * as the check threshold, the smallest n such that the correct result is
     * 1200 is used instead.
     */
    if (n >= 687737)
        return 1200;
    if (n < 8)
        return 0;

    x = n * (uint64_t)log_2;
    lx = ilog_e(x);
    y = (uint16_t)((mul2(c1_923, icbrt64(mul2(mul2(x, lx), lx))) - c4_690)
                   / log_2);
    return (y + 4) & ~7;
}

int VR_RSA_security_bits(const RSA *rsa)
{
    int bits = VR_BN_num_bits(rsa->n);

    if (rsa->version == RSA_ASN1_VERSION_MULTI) {
        /* This ought to mean that we have private key at hand. */
        int ex_primes = sk_RSA_PRIME_INFO_num(rsa->prime_infos);

        if (ex_primes <= 0 || (ex_primes + 2) > VR_rsa_multip_cap(bits))
            return 0;
    }
    return rsa_compute_security_bits(bits);
}

int VR_RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        VR_BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        VR_BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        VR_BN_clear_free(r->d);
        r->d = d;
    }

    return 1;
}

int VR_RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
    /* If the fields p and q in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->p == NULL && p == NULL)
        || (r->q == NULL && q == NULL))
        return 0;

    if (p != NULL) {
        VR_BN_clear_free(r->p);
        r->p = p;
    }
    if (q != NULL) {
        VR_BN_clear_free(r->q);
        r->q = q;
    }

    return 1;
}

int VR_RSA_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
    /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((r->dmp1 == NULL && dmp1 == NULL)
        || (r->dmq1 == NULL && dmq1 == NULL)
        || (r->iqmp == NULL && iqmp == NULL))
        return 0;

    if (dmp1 != NULL) {
        VR_BN_clear_free(r->dmp1);
        r->dmp1 = dmp1;
    }
    if (dmq1 != NULL) {
        VR_BN_clear_free(r->dmq1);
        r->dmq1 = dmq1;
    }
    if (iqmp != NULL) {
        VR_BN_clear_free(r->iqmp);
        r->iqmp = iqmp;
    }

    return 1;
}

/*
 * Is it better to export RSA_PRIME_INFO structure
 * and related functions to let user pass a triplet?
 */
int VR_RSA_set0_multi_prime_params(RSA *r, BIGNUM *primes[], BIGNUM *exps[],
                                BIGNUM *coeffs[], int pnum)
{
    STACK_OF(RSA_PRIME_INFO) *prime_infos, *old = NULL;
    RSA_PRIME_INFO *pinfo;
    int i;

    if (primes == NULL || exps == NULL || coeffs == NULL || pnum == 0)
        return 0;

    prime_infos = sk_VR_RSA_PRIME_INFO_new_reserve(NULL, pnum);
    if (prime_infos == NULL)
        return 0;

    if (r->prime_infos != NULL)
        old = r->prime_infos;

    for (i = 0; i < pnum; i++) {
        pinfo = VR_rsa_multip_info_new();
        if (pinfo == NULL)
            goto err;
        if (primes[i] != NULL && exps[i] != NULL && coeffs[i] != NULL) {
            VR_BN_free(pinfo->r);
            VR_BN_free(pinfo->d);
            VR_BN_free(pinfo->t);
            pinfo->r = primes[i];
            pinfo->d = exps[i];
            pinfo->t = coeffs[i];
        } else {
            VR_rsa_multip_info_free(pinfo);
            goto err;
        }
        (void)sk_VR_RSA_PRIME_INFO_push(prime_infos, pinfo);
    }

    r->prime_infos = prime_infos;

    if (!VR_rsa_multip_calc_product(r)) {
        r->prime_infos = old;
        goto err;
    }

    if (old != NULL) {
        /*
         * This is hard to deal with, since the old infos could
         * also be set by this function and r, d, t should not
         * be freed in that case. So currently, stay consistent
         * with other *set0* functions: just free it...
         */
        sk_VR_RSA_PRIME_INFO_pop_free(old, VR_rsa_multip_info_free);
    }

    r->version = RSA_ASN1_VERSION_MULTI;

    return 1;
 err:
    /* r, d, t should not be freed */
    sk_VR_RSA_PRIME_INFO_pop_free(prime_infos, VR_rsa_multip_info_free_ex);
    return 0;
}

void VR_RSA_get0_key(const RSA *r,
                  const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}

void VR_RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    if (p != NULL)
        *p = r->p;
    if (q != NULL)
        *q = r->q;
}

int VR_RSA_get_multi_prime_extra_count(const RSA *r)
{
    int pnum;

    pnum = sk_RSA_PRIME_INFO_num(r->prime_infos);
    if (pnum <= 0)
        pnum = 0;
    return pnum;
}

int VR_RSA_get0_multi_prime_factors(const RSA *r, const BIGNUM *primes[])
{
    int pnum, i;
    RSA_PRIME_INFO *pinfo;

    if ((pnum = VR_RSA_get_multi_prime_extra_count(r)) == 0)
        return 0;

    /*
     * return other primes
     * it's caller's responsibility to allocate oth_primes[pnum]
     */
    for (i = 0; i < pnum; i++) {
        pinfo = sk_RSA_PRIME_INFO_value(r->prime_infos, i);
        primes[i] = pinfo->r;
    }

    return 1;
}

void VR_RSA_get0_crt_params(const RSA *r,
                         const BIGNUM **dmp1, const BIGNUM **dmq1,
                         const BIGNUM **iqmp)
{
    if (dmp1 != NULL)
        *dmp1 = r->dmp1;
    if (dmq1 != NULL)
        *dmq1 = r->dmq1;
    if (iqmp != NULL)
        *iqmp = r->iqmp;
}

int VR_RSA_get0_multi_prime_crt_params(const RSA *r, const BIGNUM *exps[],
                                    const BIGNUM *coeffs[])
{
    int pnum;

    if ((pnum = VR_RSA_get_multi_prime_extra_count(r)) == 0)
        return 0;

    /* return other primes */
    if (exps != NULL || coeffs != NULL) {
        RSA_PRIME_INFO *pinfo;
        int i;

        /* it's the user's job to guarantee the buffer length */
        for (i = 0; i < pnum; i++) {
            pinfo = sk_RSA_PRIME_INFO_value(r->prime_infos, i);
            if (exps != NULL)
                exps[i] = pinfo->d;
            if (coeffs != NULL)
                coeffs[i] = pinfo->t;
        }
    }

    return 1;
}

const BIGNUM *VR_RSA_get0_n(const RSA *r)
{
    return r->n;
}

const BIGNUM *VR_RSA_get0_e(const RSA *r)
{
    return r->e;
}

const BIGNUM *VR_RSA_get0_d(const RSA *r)
{
    return r->d;
}

const BIGNUM *VR_RSA_get0_p(const RSA *r)
{
    return r->p;
}

const BIGNUM *VR_RSA_get0_q(const RSA *r)
{
    return r->q;
}

const BIGNUM *VR_RSA_get0_dmp1(const RSA *r)
{
    return r->dmp1;
}

const BIGNUM *VR_RSA_get0_dmq1(const RSA *r)
{
    return r->dmq1;
}

const BIGNUM *VR_RSA_get0_iqmp(const RSA *r)
{
    return r->iqmp;
}

void VR_RSA_clear_flags(RSA *r, int flags)
{
    r->flags &= ~flags;
}

int VR_RSA_test_flags(const RSA *r, int flags)
{
    return r->flags & flags;
}

void VR_RSA_set_flags(RSA *r, int flags)
{
    r->flags |= flags;
}

int VR_RSA_get_version(RSA *r)
{
    /* { two-prime(0), multi(1) } */
    return r->version;
}

ENGINE *VR_RSA_get0_engine(const RSA *r)
{
    return r->engine;
}

int VR_RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)
{
    /* If key type not RSA or RSA-PSS return error */
    if (ctx != NULL && ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVP_PKEY_RSA
        && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;
     return VR_EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2);
}
