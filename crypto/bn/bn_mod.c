/*
 * Copyright 1998-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "bn_lcl.h"

int VR_BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
    /*
     * like BN_mod, but returns non-negative remainder (i.e., 0 <= r < |d|
     * always holds)
     */

    if (!(BN_mod(r, m, d, ctx)))
        return 0;
    if (!r->neg)
        return 1;
    /* now   -|d| < r < 0,  so we have to set  r := r + |d| */
    return (d->neg ? VR_BN_sub : VR_BN_add) (r, r, d);
}

int VR_BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx)
{
    if (!VR_BN_add(r, a, b))
        return 0;
    return VR_BN_nnmod(r, r, m, ctx);
}

/*
 * VR_BN_mod_add variant that may be used if both a and b are non-negative and
 * less than m. The original algorithm was
 *
 *    if (!VR_BN_uadd(r, a, b))
 *       return 0;
 *    if (VR_BN_ucmp(r, m) >= 0)
 *       return VR_BN_usub(r, r, m);
 *
 * which is replaced with addition, subtracting modulus, and conditional
 * move depending on whether or not subtraction borrowed.
 */
int VR_bn_mod_add_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                         const BIGNUM *m)
{
    size_t i, ai, bi, mtop = m->top;
    BN_ULONG storage[1024 / BN_BITS2];
    BN_ULONG carry, temp, mask, *rp, *tp = storage;
    const BN_ULONG *ap, *bp;

    if (VR_bn_wexpand(r, mtop) == NULL)
        return 0;

    if (mtop > sizeof(storage) / sizeof(storage[0])
        && (tp = OPENSSL_malloc(mtop * sizeof(BN_ULONG))) == NULL)
        return 0;

    ap = a->d != NULL ? a->d : tp;
    bp = b->d != NULL ? b->d : tp;

    for (i = 0, ai = 0, bi = 0, carry = 0; i < mtop;) {
        mask = (BN_ULONG)0 - ((i - a->top) >> (8 * sizeof(i) - 1));
        temp = ((ap[ai] & mask) + carry) & BN_MASK2;
        carry = (temp < carry);

        mask = (BN_ULONG)0 - ((i - b->top) >> (8 * sizeof(i) - 1));
        tp[i] = ((bp[bi] & mask) + temp) & BN_MASK2;
        carry += (tp[i] < temp);

        i++;
        ai += (i - a->dmax) >> (8 * sizeof(i) - 1);
        bi += (i - b->dmax) >> (8 * sizeof(i) - 1);
    }
    rp = r->d;
    carry -= VR_bn_sub_words(rp, tp, m->d, mtop);
    for (i = 0; i < mtop; i++) {
        rp[i] = (carry & tp[i]) | (~carry & rp[i]);
        ((volatile BN_ULONG *)tp)[i] = 0;
    }
    r->top = mtop;
    r->flags |= BN_FLG_FIXED_TOP;
    r->neg = 0;

    if (tp != storage)
        VR_OPENSSL_free(tp);

    return 1;
}

int VR_BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m)
{
    int ret = VR_bn_mod_add_fixed_top(r, a, b, m);

    if (ret)
        VR_bn_correct_top(r);

    return ret;
}

int VR_BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx)
{
    if (!VR_BN_sub(r, a, b))
        return 0;
    return VR_BN_nnmod(r, r, m, ctx);
}

/*
 * VR_BN_mod_sub variant that may be used if both a and b are non-negative,
 * a is less than m, while b is of same bit width as m. It's implemented
 * as subtraction followed by two conditional additions.
 *
 * 0 <= a < m
 * 0 <= b < 2^w < 2*m
 *
 * after subtraction
 *
 * -2*m < r = a - b < m
 *
 * Thus it takes up to two conditional additions to make |r| positive.
 */
int VR_bn_mod_sub_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                         const BIGNUM *m)
{
    size_t i, ai, bi, mtop = m->top;
    BN_ULONG borrow, carry, ta, tb, mask, *rp;
    const BN_ULONG *ap, *bp;

    if (VR_bn_wexpand(r, mtop) == NULL)
        return 0;

    rp = r->d;
    ap = a->d != NULL ? a->d : rp;
    bp = b->d != NULL ? b->d : rp;

    for (i = 0, ai = 0, bi = 0, borrow = 0; i < mtop;) {
        mask = (BN_ULONG)0 - ((i - a->top) >> (8 * sizeof(i) - 1));
        ta = ap[ai] & mask;

        mask = (BN_ULONG)0 - ((i - b->top) >> (8 * sizeof(i) - 1));
        tb = bp[bi] & mask;
        rp[i] = ta - tb - borrow;
        if (ta != tb)
            borrow = (ta < tb);

        i++;
        ai += (i - a->dmax) >> (8 * sizeof(i) - 1);
        bi += (i - b->dmax) >> (8 * sizeof(i) - 1);
    }
    ap = m->d;
    for (i = 0, mask = 0 - borrow, carry = 0; i < mtop; i++) {
        ta = ((ap[i] & mask) + carry) & BN_MASK2;
        carry = (ta < carry);
        rp[i] = (rp[i] + ta) & BN_MASK2;
        carry += (rp[i] < ta);
    }
    borrow -= carry;
    for (i = 0, mask = 0 - borrow, carry = 0; i < mtop; i++) {
        ta = ((ap[i] & mask) + carry) & BN_MASK2;
        carry = (ta < carry);
        rp[i] = (rp[i] + ta) & BN_MASK2;
        carry += (rp[i] < ta);
    }

    r->top = mtop;
    r->flags |= BN_FLG_FIXED_TOP;
    r->neg = 0;

    return 1;
}

/*
 * VR_BN_mod_sub variant that may be used if both a and b are non-negative and
 * less than m
 */
int VR_BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                     const BIGNUM *m)
{
    if (!VR_BN_sub(r, a, b))
        return 0;
    if (r->neg)
        return VR_BN_add(r, r, m);
    return 1;
}

/* slow but works */
int VR_BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
               BN_CTX *ctx)
{
    BIGNUM *t;
    int ret = 0;

    bn_check_top(a);
    bn_check_top(b);
    bn_check_top(m);

    VR_BN_CTX_start(ctx);
    if ((t = VR_BN_CTX_get(ctx)) == NULL)
        goto err;
    if (a == b) {
        if (!VR_BN_sqr(t, a, ctx))
            goto err;
    } else {
        if (!VR_BN_mul(t, a, b, ctx))
            goto err;
    }
    if (!VR_BN_nnmod(r, t, m, ctx))
        goto err;
    bn_check_top(r);
    ret = 1;
 err:
    VR_BN_CTX_end(ctx);
    return ret;
}

int VR_BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    if (!VR_BN_sqr(r, a, ctx))
        return 0;
    /* r->neg == 0,  thus we don't need VR_BN_nnmod */
    return BN_mod(r, r, m, ctx);
}

int VR_BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
    if (!VR_BN_lshift1(r, a))
        return 0;
    bn_check_top(r);
    return VR_BN_nnmod(r, r, m, ctx);
}

/*
 * VR_BN_mod_lshift1 variant that may be used if a is non-negative and less than
 * m
 */
int VR_BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m)
{
    if (!VR_BN_lshift1(r, a))
        return 0;
    bn_check_top(r);
    if (VR_BN_cmp(r, m) >= 0)
        return VR_BN_sub(r, r, m);
    return 1;
}

int VR_BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
                  BN_CTX *ctx)
{
    BIGNUM *abs_m = NULL;
    int ret;

    if (!VR_BN_nnmod(r, a, m, ctx))
        return 0;

    if (m->neg) {
        abs_m = VR_BN_dup(m);
        if (abs_m == NULL)
            return 0;
        abs_m->neg = 0;
    }

    ret = VR_BN_mod_lshift_quick(r, r, n, (abs_m ? abs_m : m));
    bn_check_top(r);

    VR_BN_free(abs_m);
    return ret;
}

/*
 * VR_BN_mod_lshift variant that may be used if a is non-negative and less than
 * m
 */
int VR_BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m)
{
    if (r != a) {
        if (VR_BN_copy(r, a) == NULL)
            return 0;
    }

    while (n > 0) {
        int max_shift;

        /* 0 < r < m */
        max_shift = VR_BN_num_bits(m) - VR_BN_num_bits(r);
        /* max_shift >= 0 */

        if (max_shift < 0) {
            BNerr(BN_F_BN_MOD_LSHIFT_QUICK, BN_R_INPUT_NOT_REDUCED);
            return 0;
        }

        if (max_shift > n)
            max_shift = n;

        if (max_shift) {
            if (!VR_BN_lshift(r, r, max_shift))
                return 0;
            n -= max_shift;
        } else {
            if (!VR_BN_lshift1(r, r))
                return 0;
            --n;
        }

        /* VR_BN_num_bits(r) <= VR_BN_num_bits(m) */

        if (VR_BN_cmp(r, m) >= 0) {
            if (!VR_BN_sub(r, r, m))
                return 0;
        }
    }
    bn_check_top(r);

    return 1;
}
