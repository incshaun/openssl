/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include "internal/constant_time_locl.h"
#include "bn_lcl.h"

#include <stdlib.h>
#ifdef _WIN32
# include <malloc.h>
# ifndef alloca
#  define alloca _alloca
# endif
#elif defined(__GNUC__)
# ifndef alloca
#  define alloca(s) __builtin_alloca((s))
# endif
#elif defined(__sun)
# include <alloca.h>
#endif

#include "rsaz_exp.h"

#undef SPARC_T4_MONT
#if defined(OPENSSL_BN_ASM_MONT) && (defined(__sparc__) || defined(__sparc))
# include "sparc_arch.h"
extern unsigned int OPENSSL_sparcv9cap_P[];
# define SPARC_T4_MONT
#endif

/* maximum precomputation table size for *variable* sliding windows */
#define TABLE_SIZE      32

/* this one works - simple but works */
int VR_BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx)
{
    int i, bits, ret = 0;
    BIGNUM *v, *rr;

    if (VR_BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || VR_BN_get_flags(a, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by VR_BN_mod_exp_mont() */
        BNerr(BN_F_BN_EXP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    VR_BN_CTX_start(ctx);
    rr = ((r == a) || (r == p)) ? VR_BN_CTX_get(ctx) : r;
    v = VR_BN_CTX_get(ctx);
    if (rr == NULL || v == NULL)
        goto err;

    if (VR_BN_copy(v, a) == NULL)
        goto err;
    bits = VR_BN_num_bits(p);

    if (VR_BN_is_odd(p)) {
        if (VR_BN_copy(rr, a) == NULL)
            goto err;
    } else {
        if (!BN_one(rr))
            goto err;
    }

    for (i = 1; i < bits; i++) {
        if (!VR_BN_sqr(v, v, ctx))
            goto err;
        if (VR_BN_is_bit_set(p, i)) {
            if (!VR_BN_mul(rr, rr, v, ctx))
                goto err;
        }
    }
    if (r != rr && VR_BN_copy(r, rr) == NULL)
        goto err;

    ret = 1;
 err:
    VR_BN_CTX_end(ctx);
    bn_check_top(r);
    return ret;
}

int VR_BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
               BN_CTX *ctx)
{
    int ret;

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    /*-
     * For even modulus  m = 2^k*m_odd, it might make sense to compute
     * a^p mod m_odd  and  a^p mod 2^k  separately (with Montgomery
     * exponentiation for the odd part), using appropriate exponent
     * reductions, and combine the results using the CRT.
     *
     * For now, we use Montgomery only if the modulus is odd; otherwise,
     * exponentiation using the reciprocal-based quick remaindering
     * algorithm is used.
     *
     * (Timing obtained with expspeed.c [computations  a^p mod m
     * where  a, p, m  are of the same length: 256, 512, 1024, 2048,
     * 4096, 8192 bits], compared to the running time of the
     * standard algorithm:
     *
     *   VR_BN_mod_exp_mont   33 .. 40 %  [AMD K6-2, Linux, debug configuration]
     *                     55 .. 77 %  [UltraSparc processor, but
     *                                  debug-solaris-sparcv8-gcc conf.]
     *
     *   VR_BN_mod_exp_recp   50 .. 70 %  [AMD K6-2, Linux, debug configuration]
     *                     62 .. 118 % [UltraSparc, debug-solaris-sparcv8-gcc]
     *
     * On the Sparc, VR_BN_mod_exp_recp was faster than VR_BN_mod_exp_mont
     * at 2048 and more bits, but at 512 and 1024 bits, it was
     * slower even than the standard algorithm!
     *
     * "Real" timings [linux-elf, solaris-sparcv9-gcc configurations]
     * should be obtained when the new Montgomery reduction code
     * has been integrated into OpenSSL.)
     */

#define MONT_MUL_MOD
#define MONT_EXP_WORD
#define RECP_MUL_MOD

#ifdef MONT_MUL_MOD
    if (VR_BN_is_odd(m)) {
# ifdef MONT_EXP_WORD
        if (a->top == 1 && !a->neg
            && (VR_BN_get_flags(p, BN_FLG_CONSTTIME) == 0)
            && (VR_BN_get_flags(a, BN_FLG_CONSTTIME) == 0)
            && (VR_BN_get_flags(m, BN_FLG_CONSTTIME) == 0)) {
            BN_ULONG A = a->d[0];
            ret = VR_BN_mod_exp_mont_word(r, A, p, m, ctx, NULL);
        } else
# endif
            ret = VR_BN_mod_exp_mont(r, a, p, m, ctx, NULL);
    } else
#endif
#ifdef RECP_MUL_MOD
    {
        ret = VR_BN_mod_exp_recp(r, a, p, m, ctx);
    }
#else
    {
        ret = VR_BN_mod_exp_simple(r, a, p, m, ctx);
    }
#endif

    bn_check_top(r);
    return ret;
}

int VR_BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_RECP_CTX recp;

    if (VR_BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || VR_BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || VR_BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by VR_BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_RECP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bits = VR_BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (VR_BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(r);
        } else {
            ret = BN_one(r);
        }
        return ret;
    }

    VR_BN_CTX_start(ctx);
    aa = VR_BN_CTX_get(ctx);
    val[0] = VR_BN_CTX_get(ctx);
    if (val[0] == NULL)
        goto err;

    VR_BN_RECP_CTX_init(&recp);
    if (m->neg) {
        /* ignore sign of 'm' */
        if (!VR_BN_copy(aa, m))
            goto err;
        aa->neg = 0;
        if (VR_BN_RECP_CTX_set(&recp, aa, ctx) <= 0)
            goto err;
    } else {
        if (VR_BN_RECP_CTX_set(&recp, m, ctx) <= 0)
            goto err;
    }

    if (!VR_BN_nnmod(val[0], a, m, ctx))
        goto err;               /* 1 */
    if (VR_BN_is_zero(val[0])) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!VR_BN_mod_mul_reciprocal(aa, val[0], val[0], &recp, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = VR_BN_CTX_get(ctx)) == NULL) ||
                !VR_BN_mod_mul_reciprocal(val[i], val[i - 1], aa, &recp, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

    if (!BN_one(r))
        goto err;

    for (;;) {
        if (VR_BN_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!VR_BN_mod_mul_reciprocal(r, r, r, &recp, ctx))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (VR_BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!VR_BN_mod_mul_reciprocal(r, r, r, &recp, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!VR_BN_mod_mul_reciprocal(r, r, val[wvalue >> 1], &recp, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    ret = 1;
 err:
    VR_BN_CTX_end(ctx);
    VR_BN_RECP_CTX_free(&recp);
    bn_check_top(r);
    return ret;
}

int VR_BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *d, *r;
    const BIGNUM *aa;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];
    BN_MONT_CTX *mont = NULL;

    if (VR_BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || VR_BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || VR_BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        return VR_BN_mod_exp_mont_consttime(rr, a, p, m, ctx, in_mont);
    }

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    if (!VR_BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT, BN_R_CALLED_WITH_EVEN_MODULUS);
        return 0;
    }
    bits = VR_BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (VR_BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    VR_BN_CTX_start(ctx);
    d = VR_BN_CTX_get(ctx);
    r = VR_BN_CTX_get(ctx);
    val[0] = VR_BN_CTX_get(ctx);
    if (val[0] == NULL)
        goto err;

    /*
     * If this is not done, things will break in the montgomery part
     */

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = VR_BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!VR_BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    if (a->neg || VR_BN_ucmp(a, m) >= 0) {
        if (!VR_BN_nnmod(val[0], a, m, ctx))
            goto err;
        aa = val[0];
    } else
        aa = a;
    if (!VR_bn_to_mont_fixed_top(val[0], aa, mont, ctx))
        goto err;               /* 1 */

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!VR_bn_mul_mont_fixed_top(d, val[0], val[0], mont, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = VR_BN_CTX_get(ctx)) == NULL) ||
                !VR_bn_mul_mont_fixed_top(val[i], val[i - 1], d, mont, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

#if 1                           /* by Shay Gueron's suggestion */
    j = m->top;                 /* borrow j */
    if (m->d[j - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
        if (VR_bn_wexpand(r, j) == NULL)
            goto err;
        /* 2^(top*BN_BITS2) - m */
        r->d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < j; i++)
            r->d[i] = (~m->d[i]) & BN_MASK2;
        r->top = j;
        r->flags |= BN_FLG_FIXED_TOP;
    } else
#endif
    if (!VR_bn_to_mont_fixed_top(r, VR_BN_value_one(), mont, ctx))
        goto err;
    for (;;) {
        if (VR_BN_is_bit_set(p, wstart) == 0) {
            if (!start) {
                if (!VR_bn_mul_mont_fixed_top(r, r, r, mont, ctx))
                    goto err;
            }
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (VR_BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!VR_bn_mul_mont_fixed_top(r, r, r, mont, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!VR_bn_mul_mont_fixed_top(r, r, val[wvalue >> 1], mont, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    /*
     * Done with zero-padded intermediate BIGNUMs. Final VR_BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     */
#if defined(SPARC_T4_MONT)
    if (OPENSSL_sparcv9cap_P[0] & (SPARCV9_VIS3 | SPARCV9_PREFER_FPU)) {
        j = mont->N.top;        /* borrow j */
        val[0]->d[0] = 1;       /* borrow val[0] */
        for (i = 1; i < j; i++)
            val[0]->d[i] = 0;
        val[0]->top = j;
        if (!VR_BN_mod_mul_montgomery(rr, r, val[0], mont, ctx))
            goto err;
    } else
#endif
    if (!VR_BN_from_montgomery(rr, r, mont, ctx))
        goto err;
    ret = 1;
 err:
    if (in_mont == NULL)
        VR_BN_MONT_CTX_free(mont);
    VR_BN_CTX_end(ctx);
    bn_check_top(rr);
    return ret;
}

static BN_ULONG bn_get_bits(const BIGNUM *a, int bitpos)
{
    BN_ULONG ret = 0;
    int wordpos;

    wordpos = bitpos / BN_BITS2;
    bitpos %= BN_BITS2;
    if (wordpos >= 0 && wordpos < a->top) {
        ret = a->d[wordpos] & BN_MASK2;
        if (bitpos) {
            ret >>= bitpos;
            if (++wordpos < a->top)
                ret |= a->d[wordpos] << (BN_BITS2 - bitpos);
        }
    }

    return ret & BN_MASK2;
}

/*
 * VR_BN_mod_exp_mont_consttime() stores the precomputed powers in a specific
 * layout so that accessing any of these table values shows the same access
 * pattern as far as cache lines are concerned.  The following functions are
 * used to transfer a BIGNUM from/to that table.
 */

static int MOD_EXP_CTIME_COPY_TO_PREBUF(const BIGNUM *b, int top,
                                        unsigned char *buf, int idx,
                                        int window)
{
    int i, j;
    int width = 1 << window;
    BN_ULONG *table = (BN_ULONG *)buf;

    if (top > b->top)
        top = b->top;           /* this works because 'buf' is explicitly
                                 * zeroed */
    for (i = 0, j = idx; i < top; i++, j += width) {
        table[j] = b->d[i];
    }

    return 1;
}

static int MOD_EXP_CTIME_COPY_FROM_PREBUF(BIGNUM *b, int top,
                                          unsigned char *buf, int idx,
                                          int window)
{
    int i, j;
    int width = 1 << window;
    /*
     * We declare table 'volatile' in order to discourage compiler
     * from reordering loads from the table. Concern is that if
     * reordered in specific manner loads might give away the
     * information we are trying to conceal. Some would argue that
     * compiler can reorder them anyway, but it can as well be
     * argued that doing so would be violation of standard...
     */
    volatile BN_ULONG *table = (volatile BN_ULONG *)buf;

    if (VR_bn_wexpand(b, top) == NULL)
        return 0;

    if (window <= 3) {
        for (i = 0; i < top; i++, table += width) {
            BN_ULONG acc = 0;

            for (j = 0; j < width; j++) {
                acc |= table[j] &
                       ((BN_ULONG)0 - (constant_time_eq_int(j,idx)&1));
            }

            b->d[i] = acc;
        }
    } else {
        int xstride = 1 << (window - 2);
        BN_ULONG y0, y1, y2, y3;

        i = idx >> (window - 2);        /* equivalent of idx / xstride */
        idx &= xstride - 1;             /* equivalent of idx % xstride */

        y0 = (BN_ULONG)0 - (constant_time_eq_int(i,0)&1);
        y1 = (BN_ULONG)0 - (constant_time_eq_int(i,1)&1);
        y2 = (BN_ULONG)0 - (constant_time_eq_int(i,2)&1);
        y3 = (BN_ULONG)0 - (constant_time_eq_int(i,3)&1);

        for (i = 0; i < top; i++, table += width) {
            BN_ULONG acc = 0;

            for (j = 0; j < xstride; j++) {
                acc |= ( (table[j + 0 * xstride] & y0) |
                         (table[j + 1 * xstride] & y1) |
                         (table[j + 2 * xstride] & y2) |
                         (table[j + 3 * xstride] & y3) )
                       & ((BN_ULONG)0 - (constant_time_eq_int(j,idx)&1));
            }

            b->d[i] = acc;
        }
    }

    b->top = top;
    b->flags |= BN_FLG_FIXED_TOP;
    return 1;
}

/*
 * Given a pointer value, compute the next address that is a cache line
 * multiple.
 */
#define MOD_EXP_CTIME_ALIGN(x_) \
        ((unsigned char*)(x_) + (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - (((size_t)(x_)) & (MOD_EXP_CTIME_MIN_CACHE_LINE_MASK))))

/*
 * This variant of VR_BN_mod_exp_mont() uses fixed windows and the special
 * precomputation memory layout to limit data-dependency to a minimum to
 * protect secret exponents (cf. the hyper-threading timing attacks pointed
 * out by Colin Percival,
 * http://www.daemonology.net/hyperthreading-considered-harmful/)
 */
int VR_BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              BN_MONT_CTX *in_mont)
{
    int i, bits, ret = 0, window, wvalue, wmask, window0;
    int top;
    BN_MONT_CTX *mont = NULL;

    int numPowers;
    unsigned char *powerbufFree = NULL;
    int powerbufLen = 0;
    unsigned char *powerbuf = NULL;
    BIGNUM tmp, am;
#if defined(SPARC_T4_MONT)
    unsigned int t4 = 0;
#endif

    bn_check_top(a);
    bn_check_top(p);
    bn_check_top(m);

    if (!VR_BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT_CONSTTIME, BN_R_CALLED_WITH_EVEN_MODULUS);
        return 0;
    }

    top = m->top;

    /*
     * Use all bits stored in |p|, rather than |VR_BN_num_bits|, so we do not leak
     * whether the top bits are zero.
     */
    bits = p->top * BN_BITS2;
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (VR_BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }

    VR_BN_CTX_start(ctx);

    /*
     * Allocate a montgomery context if it was not supplied by the caller. If
     * this is not done, things will break in the montgomery part.
     */
    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = VR_BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!VR_BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    if (a->neg || VR_BN_ucmp(a, m) >= 0) {
        BIGNUM *reduced = VR_BN_CTX_get(ctx);
        if (reduced == NULL
            || !VR_BN_nnmod(reduced, a, m, ctx)) {
            goto err;
        }
        a = reduced;
    }

#ifdef RSAZ_ENABLED
    /*
     * If the size of the operands allow it, perform the optimized
     * RSAZ exponentiation. For further information see
     * crypto/bn/rsaz_exp.c and accompanying assembly modules.
     */
    if ((16 == a->top) && (16 == p->top) && (VR_BN_num_bits(m) == 1024)
        && VR_rsaz_avx2_eligible()) {
        if (NULL == VR_bn_wexpand(rr, 16))
            goto err;
        VR_RSAZ_1024_mod_exp_avx2(rr->d, a->d, p->d, m->d, mont->RR.d,
                               mont->n0[0]);
        rr->top = 16;
        rr->neg = 0;
        VR_bn_correct_top(rr);
        ret = 1;
        goto err;
    } else if ((8 == a->top) && (8 == p->top) && (VR_BN_num_bits(m) == 512)) {
        if (NULL == VR_bn_wexpand(rr, 8))
            goto err;
        VR_RSAZ_512_mod_exp(rr->d, a->d, p->d, m->d, mont->n0[0], mont->RR.d);
        rr->top = 8;
        rr->neg = 0;
        VR_bn_correct_top(rr);
        ret = 1;
        goto err;
    }
#endif

    /* Get the window size to use with size of p. */
    window = BN_window_bits_for_ctime_exponent_size(bits);
#if defined(SPARC_T4_MONT)
    if (window >= 5 && (top & 15) == 0 && top <= 64 &&
        (OPENSSL_sparcv9cap_P[1] & (CFR_MONTMUL | CFR_MONTSQR)) ==
        (CFR_MONTMUL | CFR_MONTSQR) && (t4 = OPENSSL_sparcv9cap_P[0]))
        window = 5;
    else
#endif
#if defined(OPENSSL_BN_ASM_MONT5)
    if (window >= 5) {
        window = 5;             /* ~5% improvement for RSA2048 sign, and even
                                 * for RSA4096 */
        /* reserve space for mont->N.d[] copy */
        powerbufLen += top * sizeof(mont->N.d[0]);
    }
#endif
    (void)0;

    /*
     * Allocate a buffer large enough to hold all of the pre-computed powers
     * of am, am itself and tmp.
     */
    numPowers = 1 << window;
    powerbufLen += sizeof(m->d[0]) * (top * numPowers +
                                      ((2 * top) >
                                       numPowers ? (2 * top) : numPowers));
#ifdef alloca
    if (powerbufLen < 3072)
        powerbufFree =
            alloca(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH);
    else
#endif
        if ((powerbufFree =
             OPENSSL_malloc(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH))
            == NULL)
        goto err;

    powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
    memset(powerbuf, 0, powerbufLen);

#ifdef alloca
    if (powerbufLen < 3072)
        powerbufFree = NULL;
#endif

    /* lay down tmp and am right after powers table */
    tmp.d = (BN_ULONG *)(powerbuf + sizeof(m->d[0]) * top * numPowers);
    am.d = tmp.d + top;
    tmp.top = am.top = 0;
    tmp.dmax = am.dmax = top;
    tmp.neg = am.neg = 0;
    tmp.flags = am.flags = BN_FLG_STATIC_DATA;

    /* prepare a^0 in Montgomery domain */
#if 1                           /* by Shay Gueron's suggestion */
    if (m->d[top - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
        /* 2^(top*BN_BITS2) - m */
        tmp.d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < top; i++)
            tmp.d[i] = (~m->d[i]) & BN_MASK2;
        tmp.top = top;
    } else
#endif
    if (!VR_bn_to_mont_fixed_top(&tmp, VR_BN_value_one(), mont, ctx))
        goto err;

    /* prepare a^1 in Montgomery domain */
    if (!VR_bn_to_mont_fixed_top(&am, a, mont, ctx))
        goto err;

#if defined(SPARC_T4_MONT)
    if (t4) {
        typedef int (*bn_pwr5_mont_f) (BN_ULONG *tp, const BN_ULONG *np,
                                       const BN_ULONG *n0, const void *table,
                                       int power, int bits);
        int bn_pwr5_mont_t4_8(BN_ULONG *tp, const BN_ULONG *np,
                              const BN_ULONG *n0, const void *table,
                              int power, int bits);
        int bn_pwr5_mont_t4_16(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        int bn_pwr5_mont_t4_24(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        int bn_pwr5_mont_t4_32(BN_ULONG *tp, const BN_ULONG *np,
                               const BN_ULONG *n0, const void *table,
                               int power, int bits);
        static const bn_pwr5_mont_f pwr5_funcs[4] = {
            bn_pwr5_mont_t4_8, bn_pwr5_mont_t4_16,
            bn_pwr5_mont_t4_24, bn_pwr5_mont_t4_32
        };
        bn_pwr5_mont_f pwr5_worker = pwr5_funcs[top / 16 - 1];

        typedef int (*VR_bn_mul_mont_f) (BN_ULONG *rp, const BN_ULONG *ap,
                                      const void *bp, const BN_ULONG *np,
                                      const BN_ULONG *n0);
        int VR_bn_mul_mont_t4_8(BN_ULONG *rp, const BN_ULONG *ap, const void *bp,
                             const BN_ULONG *np, const BN_ULONG *n0);
        int VR_bn_mul_mont_t4_16(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        int VR_bn_mul_mont_t4_24(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        int VR_bn_mul_mont_t4_32(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0);
        static const VR_bn_mul_mont_f mul_funcs[4] = {
            VR_bn_mul_mont_t4_8, VR_bn_mul_mont_t4_16,
            VR_bn_mul_mont_t4_24, VR_bn_mul_mont_t4_32
        };
        VR_bn_mul_mont_f mul_worker = mul_funcs[top / 16 - 1];

        void VR_bn_mul_mont_vis3(BN_ULONG *rp, const BN_ULONG *ap,
                              const void *bp, const BN_ULONG *np,
                              const BN_ULONG *n0, int num);
        void VR_bn_mul_mont_t4(BN_ULONG *rp, const BN_ULONG *ap,
                            const void *bp, const BN_ULONG *np,
                            const BN_ULONG *n0, int num);
        void VR_bn_mul_mont_gather5_t4(BN_ULONG *rp, const BN_ULONG *ap,
                                    const void *table, const BN_ULONG *np,
                                    const BN_ULONG *n0, int num, int power);
        void bn_flip_n_scatter5_t4(const BN_ULONG *inp, size_t num,
                                   void *table, size_t power);
        void VR_bn_gather5_t4(BN_ULONG *out, size_t num,
                           void *table, size_t power);
        void bn_flip_t4(BN_ULONG *dst, BN_ULONG *src, size_t num);

        BN_ULONG *np = mont->N.d, *n0 = mont->n0;
        int stride = 5 * (6 - (top / 16 - 1)); /* multiple of 5, but less
                                                * than 32 */

        /*
         * VR_BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG[_DEBUG] build]...
         */
        for (i = am.top; i < top; i++)
            am.d[i] = 0;
        for (i = tmp.top; i < top; i++)
            tmp.d[i] = 0;

        bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, 0);
        bn_flip_n_scatter5_t4(am.d, top, powerbuf, 1);
        if (!(*mul_worker) (tmp.d, am.d, am.d, np, n0) &&
            !(*mul_worker) (tmp.d, am.d, am.d, np, n0))
            VR_bn_mul_mont_vis3(tmp.d, am.d, am.d, np, n0, top);
        bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, 2);

        for (i = 3; i < 32; i++) {
            /* Calculate a^i = a^(i-1) * a */
            if (!(*mul_worker) (tmp.d, tmp.d, am.d, np, n0) &&
                !(*mul_worker) (tmp.d, tmp.d, am.d, np, n0))
                VR_bn_mul_mont_vis3(tmp.d, tmp.d, am.d, np, n0, top);
            bn_flip_n_scatter5_t4(tmp.d, top, powerbuf, i);
        }

        /* switch to 64-bit domain */
        np = alloca(top * sizeof(BN_ULONG));
        top /= 2;
        bn_flip_t4(np, mont->N.d, top);

        /*
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         */
        window0 = (bits - 1) % 5 + 1;
        wmask = (1 << window0) - 1;
        bits -= window0;
        wvalue = bn_get_bits(p, bits) & wmask;
        VR_bn_gather5_t4(tmp.d, top, powerbuf, wvalue);

        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        while (bits > 0) {
            if (bits < stride)
                stride = bits;
            bits -= stride;
            wvalue = bn_get_bits(p, bits);

            if ((*pwr5_worker) (tmp.d, np, n0, powerbuf, wvalue, stride))
                continue;
            /* retry once and fall back */
            if ((*pwr5_worker) (tmp.d, np, n0, powerbuf, wvalue, stride))
                continue;

            bits += stride - 5;
            wvalue >>= stride - 5;
            wvalue &= 31;
            VR_bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            VR_bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            VR_bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            VR_bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            VR_bn_mul_mont_t4(tmp.d, tmp.d, tmp.d, np, n0, top);
            VR_bn_mul_mont_gather5_t4(tmp.d, tmp.d, powerbuf, np, n0, top,
                                   wvalue);
        }

        bn_flip_t4(tmp.d, tmp.d, top);
        top *= 2;
        /* back to 32-bit domain */
        tmp.top = top;
        VR_bn_correct_top(&tmp);
        VR_OPENSSL_cleanse(np, top * sizeof(BN_ULONG));
    } else
#endif
#if defined(OPENSSL_BN_ASM_MONT5)
    if (window == 5 && top > 1) {
        /*
         * This optimization uses ideas from http://eprint.iacr.org/2011/239,
         * specifically optimization of cache-timing attack countermeasures
         * and pre-computation optimization.
         */

        /*
         * Dedicated window==4 case improves 512-bit RSA sign by ~15%, but as
         * 512-bit RSA is hardly relevant, we omit it to spare size...
         */
        void VR_bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap,
                                 const void *table, const BN_ULONG *np,
                                 const BN_ULONG *n0, int num, int power);
        void VR_bn_scatter5(const BN_ULONG *inp, size_t num,
                         void *table, size_t power);
        void VR_bn_gather5(BN_ULONG *out, size_t num, void *table, size_t power);
        void VR_bn_power5(BN_ULONG *rp, const BN_ULONG *ap,
                       const void *table, const BN_ULONG *np,
                       const BN_ULONG *n0, int num, int power);
        int VR_bn_get_bits5(const BN_ULONG *ap, int off);
        int VR_bn_from_montgomery(BN_ULONG *rp, const BN_ULONG *ap,
                               const BN_ULONG *not_used, const BN_ULONG *np,
                               const BN_ULONG *n0, int num);

        BN_ULONG *n0 = mont->n0, *np;

        /*
         * VR_BN_to_montgomery can contaminate words above .top [in
         * BN_DEBUG[_DEBUG] build]...
         */
        for (i = am.top; i < top; i++)
            am.d[i] = 0;
        for (i = tmp.top; i < top; i++)
            tmp.d[i] = 0;

        /*
         * copy mont->N.d[] to improve cache locality
         */
        for (np = am.d + top, i = 0; i < top; i++)
            np[i] = mont->N.d[i];

        VR_bn_scatter5(tmp.d, top, powerbuf, 0);
        VR_bn_scatter5(am.d, am.top, powerbuf, 1);
        VR_bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
        VR_bn_scatter5(tmp.d, top, powerbuf, 2);

# if 0
        for (i = 3; i < 32; i++) {
            /* Calculate a^i = a^(i-1) * a */
            VR_bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            VR_bn_scatter5(tmp.d, top, powerbuf, i);
        }
# else
        /* same as above, but uses squaring for 1/2 of operations */
        for (i = 4; i < 32; i *= 2) {
            VR_bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            VR_bn_scatter5(tmp.d, top, powerbuf, i);
        }
        for (i = 3; i < 8; i += 2) {
            int j;
            VR_bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            VR_bn_scatter5(tmp.d, top, powerbuf, i);
            for (j = 2 * i; j < 32; j *= 2) {
                VR_bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                VR_bn_scatter5(tmp.d, top, powerbuf, j);
            }
        }
        for (; i < 16; i += 2) {
            VR_bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            VR_bn_scatter5(tmp.d, top, powerbuf, i);
            VR_bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
            VR_bn_scatter5(tmp.d, top, powerbuf, 2 * i);
        }
        for (; i < 32; i += 2) {
            VR_bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np, n0, top, i - 1);
            VR_bn_scatter5(tmp.d, top, powerbuf, i);
        }
# endif
        /*
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         */
        window0 = (bits - 1) % 5 + 1;
        wmask = (1 << window0) - 1;
        bits -= window0;
        wvalue = bn_get_bits(p, bits) & wmask;
        VR_bn_gather5(tmp.d, top, powerbuf, wvalue);

        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        if (top & 7) {
            while (bits > 0) {
                VR_bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                VR_bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                VR_bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                VR_bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                VR_bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
                VR_bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top,
                                    VR_bn_get_bits5(p->d, bits -= 5));
            }
        } else {
            while (bits > 0) {
                VR_bn_power5(tmp.d, tmp.d, powerbuf, np, n0, top,
                          VR_bn_get_bits5(p->d, bits -= 5));
            }
        }

        ret = VR_bn_from_montgomery(tmp.d, tmp.d, NULL, np, n0, top);
        tmp.top = top;
        VR_bn_correct_top(&tmp);
        if (ret) {
            if (!VR_BN_copy(rr, &tmp))
                ret = 0;
            goto err;           /* non-zero ret means it's not error */
        }
    } else
#endif
    {
        if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 0, window))
            goto err;
        if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&am, top, powerbuf, 1, window))
            goto err;

        /*
         * If the window size is greater than 1, then calculate
         * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1) (even
         * powers could instead be computed as (a^(i/2))^2 to use the slight
         * performance advantage of sqr over mul).
         */
        if (window > 1) {
            if (!VR_bn_mul_mont_fixed_top(&tmp, &am, &am, mont, ctx))
                goto err;
            if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, 2,
                                              window))
                goto err;
            for (i = 3; i < numPowers; i++) {
                /* Calculate a^i = a^(i-1) * a */
                if (!VR_bn_mul_mont_fixed_top(&tmp, &am, &tmp, mont, ctx))
                    goto err;
                if (!MOD_EXP_CTIME_COPY_TO_PREBUF(&tmp, top, powerbuf, i,
                                                  window))
                    goto err;
            }
        }

        /*
         * The exponent may not have a whole number of fixed-size windows.
         * To simplify the main loop, the initial window has between 1 and
         * full-window-size bits such that what remains is always a whole
         * number of windows
         */
        window0 = (bits - 1) % window + 1;
        wmask = (1 << window0) - 1;
        bits -= window0;
        wvalue = bn_get_bits(p, bits) & wmask;
        if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&tmp, top, powerbuf, wvalue,
                                            window))
            goto err;

        wmask = (1 << window) - 1;
        /*
         * Scan the exponent one window at a time starting from the most
         * significant bits.
         */
        while (bits > 0) {

            /* Square the result window-size times */
            for (i = 0; i < window; i++)
                if (!VR_bn_mul_mont_fixed_top(&tmp, &tmp, &tmp, mont, ctx))
                    goto err;

            /*
             * Get a window's worth of bits from the exponent
             * This avoids calling VR_BN_is_bit_set for each bit, which
             * is not only slower but also makes each bit vulnerable to
             * EM (and likely other) side-channel attacks like One&Done
             * (for details see "One&Done: A Single-Decryption EM-Based
             *  Attack on OpenSSL's Constant-Time Blinded RSA" by M. Alam,
             *  H. Khan, M. Dey, N. Sinha, R. Callan, A. Zajic, and
             *  M. Prvulovic, in USENIX Security'18)
             */
            bits -= window;
            wvalue = bn_get_bits(p, bits) & wmask;
            /*
             * Fetch the appropriate pre-computed value from the pre-buf
             */
            if (!MOD_EXP_CTIME_COPY_FROM_PREBUF(&am, top, powerbuf, wvalue,
                                                window))
                goto err;

            /* Multiply the result into the intermediate result */
            if (!VR_bn_mul_mont_fixed_top(&tmp, &tmp, &am, mont, ctx))
                goto err;
        }
    }

    /*
     * Done with zero-padded intermediate BIGNUMs. Final VR_BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     */
#if defined(SPARC_T4_MONT)
    if (OPENSSL_sparcv9cap_P[0] & (SPARCV9_VIS3 | SPARCV9_PREFER_FPU)) {
        am.d[0] = 1;            /* borrow am */
        for (i = 1; i < top; i++)
            am.d[i] = 0;
        if (!VR_BN_mod_mul_montgomery(rr, &tmp, &am, mont, ctx))
            goto err;
    } else
#endif
    if (!VR_BN_from_montgomery(rr, &tmp, mont, ctx))
        goto err;
    ret = 1;
 err:
    if (in_mont == NULL)
        VR_BN_MONT_CTX_free(mont);
    if (powerbuf != NULL) {
        VR_OPENSSL_cleanse(powerbuf, powerbufLen);
        VR_OPENSSL_free(powerbufFree);
    }
    VR_BN_CTX_end(ctx);
    return ret;
}

int VR_BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    BN_MONT_CTX *mont = NULL;
    int b, bits, ret = 0;
    int r_is_one;
    BN_ULONG w, next_w;
    BIGNUM *r, *t;
    BIGNUM *swap_tmp;
#define BN_MOD_MUL_WORD(r, w, m) \
                (VR_BN_mul_word(r, (w)) && \
                (/* VR_BN_ucmp(r, (m)) < 0 ? 1 :*/  \
                        (BN_mod(t, r, m, ctx) && (swap_tmp = r, r = t, t = swap_tmp, 1))))
    /*
     * BN_MOD_MUL_WORD is only used with 'w' large, so the VR_BN_ucmp test is
     * probably more overhead than always using BN_mod (which uses VR_BN_copy if
     * a similar test returns true).
     */
    /*
     * We can use BN_mod and do not need VR_BN_nnmod because our accumulator is
     * never negative (the result of BN_mod does not depend on the sign of
     * the modulus).
     */
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
                (VR_BN_set_word(r, (w)) && VR_BN_to_montgomery(r, r, (mont), ctx))

    if (VR_BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || VR_BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by VR_BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_MONT_WORD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bn_check_top(p);
    bn_check_top(m);

    if (!VR_BN_is_odd(m)) {
        BNerr(BN_F_BN_MOD_EXP_MONT_WORD, BN_R_CALLED_WITH_EVEN_MODULUS);
        return 0;
    }
    if (m->top == 1)
        a %= m->d[0];           /* make sure that 'a' is reduced */

    bits = VR_BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (VR_BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(rr);
        } else {
            ret = BN_one(rr);
        }
        return ret;
    }
    if (a == 0) {
        BN_zero(rr);
        ret = 1;
        return ret;
    }

    VR_BN_CTX_start(ctx);
    r = VR_BN_CTX_get(ctx);
    t = VR_BN_CTX_get(ctx);
    if (t == NULL)
        goto err;

    if (in_mont != NULL)
        mont = in_mont;
    else {
        if ((mont = VR_BN_MONT_CTX_new()) == NULL)
            goto err;
        if (!VR_BN_MONT_CTX_set(mont, m, ctx))
            goto err;
    }

    r_is_one = 1;               /* except for Montgomery factor */

    /* bits-1 >= 0 */

    /* The result is accumulated in the product r*w. */
    w = a;                      /* bit 'bits-1' of 'p' is always set */
    for (b = bits - 2; b >= 0; b--) {
        /* First, square r*w. */
        next_w = w * w;
        if ((next_w / w) != w) { /* overflow */
            if (r_is_one) {
                if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                    goto err;
                r_is_one = 0;
            } else {
                if (!BN_MOD_MUL_WORD(r, w, m))
                    goto err;
            }
            next_w = 1;
        }
        w = next_w;
        if (!r_is_one) {
            if (!VR_BN_mod_mul_montgomery(r, r, r, mont, ctx))
                goto err;
        }

        /* Second, multiply r*w by 'a' if exponent bit is set. */
        if (VR_BN_is_bit_set(p, b)) {
            next_w = w * a;
            if ((next_w / a) != w) { /* overflow */
                if (r_is_one) {
                    if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                        goto err;
                    r_is_one = 0;
                } else {
                    if (!BN_MOD_MUL_WORD(r, w, m))
                        goto err;
                }
                next_w = a;
            }
            w = next_w;
        }
    }

    /* Finally, set r:=r*w. */
    if (w != 1) {
        if (r_is_one) {
            if (!BN_TO_MONTGOMERY_WORD(r, w, mont))
                goto err;
            r_is_one = 0;
        } else {
            if (!BN_MOD_MUL_WORD(r, w, m))
                goto err;
        }
    }

    if (r_is_one) {             /* can happen only if a == 1 */
        if (!BN_one(rr))
            goto err;
    } else {
        if (!VR_BN_from_montgomery(rr, r, mont, ctx))
            goto err;
    }
    ret = 1;
 err:
    if (in_mont == NULL)
        VR_BN_MONT_CTX_free(mont);
    VR_BN_CTX_end(ctx);
    bn_check_top(rr);
    return ret;
}

/* The old fallback, simple version :-) */
int VR_BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                      const BIGNUM *m, BN_CTX *ctx)
{
    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM *d;
    /* Table of variables obtained from 'ctx' */
    BIGNUM *val[TABLE_SIZE];

    if (VR_BN_get_flags(p, BN_FLG_CONSTTIME) != 0
            || VR_BN_get_flags(a, BN_FLG_CONSTTIME) != 0
            || VR_BN_get_flags(m, BN_FLG_CONSTTIME) != 0) {
        /* BN_FLG_CONSTTIME only supported by VR_BN_mod_exp_mont() */
        BNerr(BN_F_BN_MOD_EXP_SIMPLE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    bits = VR_BN_num_bits(p);
    if (bits == 0) {
        /* x**0 mod 1, or x**0 mod -1 is still zero. */
        if (VR_BN_abs_is_word(m, 1)) {
            ret = 1;
            BN_zero(r);
        } else {
            ret = BN_one(r);
        }
        return ret;
    }

    VR_BN_CTX_start(ctx);
    d = VR_BN_CTX_get(ctx);
    val[0] = VR_BN_CTX_get(ctx);
    if (val[0] == NULL)
        goto err;

    if (!VR_BN_nnmod(val[0], a, m, ctx))
        goto err;               /* 1 */
    if (VR_BN_is_zero(val[0])) {
        BN_zero(r);
        ret = 1;
        goto err;
    }

    window = BN_window_bits_for_exponent_size(bits);
    if (window > 1) {
        if (!VR_BN_mod_mul(d, val[0], val[0], m, ctx))
            goto err;           /* 2 */
        j = 1 << (window - 1);
        for (i = 1; i < j; i++) {
            if (((val[i] = VR_BN_CTX_get(ctx)) == NULL) ||
                !VR_BN_mod_mul(val[i], val[i - 1], d, m, ctx))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

    if (!BN_one(r))
        goto err;

    for (;;) {
        if (VR_BN_is_bit_set(p, wstart) == 0) {
            if (!start)
                if (!VR_BN_mod_mul(r, r, r, m, ctx))
                    goto err;
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (VR_BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!VR_BN_mod_mul(r, r, r, m, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!VR_BN_mod_mul(r, r, val[wvalue >> 1], m, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }
    ret = 1;
 err:
    VR_BN_CTX_end(ctx);
    bn_check_top(r);
    return ret;
}
