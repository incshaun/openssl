/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/bn.h>
#include "dh_locl.h"
#include <openssl/engine.h>

int VR_DH_set_method(DH *dh, const DH_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const DH_METHOD *mtmp;
    mtmp = dh->meth;
    if (mtmp->finish)
        mtmp->finish(dh);
#ifndef OPENSSL_NO_ENGINE
    VR_ENGINE_finish(dh->engine);
    dh->engine = NULL;
#endif
    dh->meth = meth;
    if (meth->init)
        meth->init(dh);
    return 1;
}

DH *VR_DH_new(void)
{
    return VR_DH_new_method(NULL);
}

DH *VR_DH_new_method(ENGINE *engine)
{
    DH *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = VR_CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        VR_OPENSSL_free(ret);
        return NULL;
    }

    ret->meth = VR_DH_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    ret->flags = ret->meth->flags;  /* early default init */
    if (engine) {
        if (!VR_ENGINE_init(engine)) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
        ret->engine = engine;
    } else
        ret->engine = VR_ENGINE_get_default_DH();
    if (ret->engine) {
        ret->meth = VR_ENGINE_get_DH(ret->engine);
        if (ret->meth == NULL) {
            DHerr(DH_F_DH_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
    }
#endif

    ret->flags = ret->meth->flags;

    if (!VR_CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DH, ret, &ret->ex_data))
        goto err;

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        DHerr(DH_F_DH_NEW_METHOD, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

 err:
    VR_DH_free(ret);
    return NULL;
}

void VR_DH_free(DH *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("DH", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    VR_ENGINE_finish(r->engine);
#endif

    VR_CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DH, r, &r->ex_data);

    VR_CRYPTO_THREAD_lock_free(r->lock);

    VR_BN_clear_free(r->p);
    VR_BN_clear_free(r->g);
    VR_BN_clear_free(r->q);
    VR_BN_clear_free(r->j);
    VR_OPENSSL_free(r->seed);
    VR_BN_clear_free(r->counter);
    VR_BN_clear_free(r->pub_key);
    VR_BN_clear_free(r->priv_key);
    VR_OPENSSL_free(r);
}

int VR_DH_up_ref(DH *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("DH", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

int VR_DH_set_ex_data(DH *d, int idx, void *arg)
{
    return VR_CRYPTO_set_ex_data(&d->ex_data, idx, arg);
}

void *VR_DH_get_ex_data(DH *d, int idx)
{
    return VR_CRYPTO_get_ex_data(&d->ex_data, idx);
}

int VR_DH_bits(const DH *dh)
{
    return VR_BN_num_bits(dh->p);
}

int VR_DH_size(const DH *dh)
{
    return VR_BN_num_bytes(dh->p);
}

int VR_DH_security_bits(const DH *dh)
{
    int N;
    if (dh->q)
        N = VR_BN_num_bits(dh->q);
    else if (dh->length)
        N = dh->length;
    else
        N = -1;
    return VR_BN_security_bits(VR_BN_num_bits(dh->p), N);
}


void VR_DH_get0_pqg(const DH *dh,
                 const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = dh->p;
    if (q != NULL)
        *q = dh->q;
    if (g != NULL)
        *g = dh->g;
}

int VR_DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
        || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        VR_BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        VR_BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        VR_BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = VR_BN_num_bits(q);
    }

    return 1;
}

long VR_DH_get_length(const DH *dh)
{
    return dh->length;
}

int VR_DH_set_length(DH *dh, long length)
{
    dh->length = length;
    return 1;
}

void VR_DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}

int VR_DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    if (pub_key != NULL) {
        VR_BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        VR_BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}

const BIGNUM *VR_DH_get0_p(const DH *dh)
{
    return dh->p;
}

const BIGNUM *VR_DH_get0_q(const DH *dh)
{
    return dh->q;
}

const BIGNUM *VR_DH_get0_g(const DH *dh)
{
    return dh->g;
}

const BIGNUM *VR_DH_get0_priv_key(const DH *dh)
{
    return dh->priv_key;
}

const BIGNUM *VR_DH_get0_pub_key(const DH *dh)
{
    return dh->pub_key;
}

void VR_DH_clear_flags(DH *dh, int flags)
{
    dh->flags &= ~flags;
}

int VR_DH_test_flags(const DH *dh, int flags)
{
    return dh->flags & flags;
}

void VR_DH_set_flags(DH *dh, int flags)
{
    dh->flags |= flags;
}

ENGINE *VR_DH_get0_engine(DH *dh)
{
    return dh->engine;
}
