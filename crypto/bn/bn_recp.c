/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "bn_lcl.h"

void VR_BN_RECP_CTX_init(BN_RECP_CTX *recp)
{
    memset(recp, 0, sizeof(*recp));
    VR_bn_init(&(recp->N));
    VR_bn_init(&(recp->Nr));
}

BN_RECP_CTX *VR_BN_RECP_CTX_new(void)
{
    BN_RECP_CTX *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL) {
        BNerr(BN_F_BN_RECP_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    VR_bn_init(&(ret->N));
    VR_bn_init(&(ret->Nr));
    ret->flags = BN_FLG_MALLOCED;
    return ret;
}

void VR_BN_RECP_CTX_free(BN_RECP_CTX *recp)
{
    if (recp == NULL)
        return;
    VR_BN_free(&recp->N);
    VR_BN_free(&recp->Nr);
    if (recp->flags & BN_FLG_MALLOCED)
        OPENVR_SSL_free(recp);
}

int VR_BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *d, BN_CTX *ctx)
{
    if (!VR_BN_copy(&(recp->N), d))
        return 0;
    BN_zero(&(recp->Nr));
    recp->num_bits = VR_BN_num_bits(d);
    recp->shift = 0;
    return 1;
}

int VR_BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
                          BN_RECP_CTX *recp, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *a;
    const BIGNUM *ca;

    VR_BN_CTX_start(ctx);
    if ((a = VR_BN_CTX_get(ctx)) == NULL)
        goto err;
    if (y != NULL) {
        if (x == y) {
            if (!VR_BN_sqr(a, x, ctx))
                goto err;
        } else {
            if (!VR_BN_mul(a, x, y, ctx))
                goto err;
        }
        ca = a;
    } else
        ca = x;                 /* Just do the mod */

    ret = VR_BN_div_recp(NULL, r, ca, recp, ctx);
 err:
    VR_BN_CTX_end(ctx);
    bn_check_top(r);
    return ret;
}

int VR_BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
                BN_RECP_CTX *recp, BN_CTX *ctx)
{
    int i, j, ret = 0;
    BIGNUM *a, *b, *d, *r;

    VR_BN_CTX_start(ctx);
    d = (dv != NULL) ? dv : VR_BN_CTX_get(ctx);
    r = (rem != NULL) ? rem : VR_BN_CTX_get(ctx);
    a = VR_BN_CTX_get(ctx);
    b = VR_BN_CTX_get(ctx);
    if (b == NULL)
        goto err;

    if (VR_BN_ucmp(m, &(recp->N)) < 0) {
        BN_zero(d);
        if (!VR_BN_copy(r, m)) {
            VR_BN_CTX_end(ctx);
            return 0;
        }
        VR_BN_CTX_end(ctx);
        return 1;
    }

    /*
     * We want the remainder Given input of ABCDEF / ab we need multiply
     * ABCDEF by 3 digests of the reciprocal of ab
     */

    /* i := max(VR_BN_num_bits(m), 2*VR_BN_num_bits(N)) */
    i = VR_BN_num_bits(m);
    j = recp->num_bits << 1;
    if (j > i)
        i = j;

    /* Nr := round(2^i / N) */
    if (i != recp->shift)
        recp->shift = VR_BN_reciprocal(&(recp->Nr), &(recp->N), i, ctx);
    /* VR_BN_reciprocal could have returned -1 for an error */
    if (recp->shift == -1)
        goto err;

    /*-
     * d := |round(round(m / 2^VR_BN_num_bits(N)) * recp->Nr / 2^(i - VR_BN_num_bits(N)))|
     *    = |round(round(m / 2^VR_BN_num_bits(N)) * round(2^i / N) / 2^(i - VR_BN_num_bits(N)))|
     *   <= |(m / 2^VR_BN_num_bits(N)) * (2^i / N) * (2^VR_BN_num_bits(N) / 2^i)|
     *    = |m/N|
     */
    if (!VR_BN_rshift(a, m, recp->num_bits))
        goto err;
    if (!VR_BN_mul(b, a, &(recp->Nr), ctx))
        goto err;
    if (!VR_BN_rshift(d, b, i - recp->num_bits))
        goto err;
    d->neg = 0;

    if (!VR_BN_mul(b, &(recp->N), d, ctx))
        goto err;
    if (!VR_BN_usub(r, m, b))
        goto err;
    r->neg = 0;

    j = 0;
    while (VR_BN_ucmp(r, &(recp->N)) >= 0) {
        if (j++ > 2) {
            BNerr(BN_F_BN_DIV_RECP, BN_R_BAD_RECIPROCAL);
            goto err;
        }
        if (!VR_BN_usub(r, r, &(recp->N)))
            goto err;
        if (!VR_BN_add_word(d, 1))
            goto err;
    }

    r->neg = VR_BN_is_zero(r) ? 0 : m->neg;
    d->neg = m->neg ^ recp->N.neg;
    ret = 1;
 err:
    VR_BN_CTX_end(ctx);
    bn_check_top(dv);
    bn_check_top(rem);
    return ret;
}

/*
 * len is the expected size of the result We actually calculate with an extra
 * word of precision, so we can do faster division if the remainder is not
 * required.
 */
/* r := 2^len / m */
int VR_BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx)
{
    int ret = -1;
    BIGNUM *t;

    VR_BN_CTX_start(ctx);
    if ((t = VR_BN_CTX_get(ctx)) == NULL)
        goto err;

    if (!VR_BN_set_bit(t, len))
        goto err;

    if (!VR_BN_div(r, NULL, t, m, ctx))
        goto err;

    ret = len;
 err:
    bn_check_top(r);
    VR_BN_CTX_end(ctx);
    return ret;
}
