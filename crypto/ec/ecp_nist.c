/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>

#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include "ec_lcl.h"

const EC_METHOD *VR_EC_GFp_nist_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        VR_ec_GFp_simple_group_init,
        VR_ec_GFp_simple_group_finish,
        VR_ec_GFp_simple_group_clear_finish,
        VR_ec_GFp_nist_group_copy,
        VR_ec_GFp_nist_group_set_curve,
        VR_ec_GFp_simple_group_get_curve,
        VR_ec_GFp_simple_group_get_degree,
        VR_ec_group_simple_order_bits,
        VR_ec_GFp_simple_group_check_discriminant,
        VR_ec_GFp_simple_point_init,
        VR_ec_GFp_simple_point_finish,
        VR_ec_GFp_simple_point_clear_finish,
        VR_ec_GFp_simple_point_copy,
        VR_ec_GFp_simple_point_set_to_infinity,
        VR_ec_GFp_simple_set_Jprojective_coordinates_GFp,
        VR_ec_GFp_simple_get_Jprojective_coordinates_GFp,
        VR_ec_GFp_simple_point_set_affine_coordinates,
        VR_ec_GFp_simple_point_get_affine_coordinates,
        0, 0, 0,
        VR_ec_GFp_simple_add,
        VR_ec_GFp_simple_dbl,
        VR_ec_GFp_simple_invert,
        VR_ec_GFp_simple_is_at_infinity,
        VR_ec_GFp_simple_is_on_curve,
        VR_ec_GFp_simple_cmp,
        VR_ec_GFp_simple_make_affine,
        VR_ec_GFp_simple_points_make_affine,
        0 /* mul */ ,
        0 /* precompute_mult */ ,
        0 /* have_precompute_mult */ ,
        VR_ec_GFp_nist_field_mul,
        VR_ec_GFp_nist_field_sqr,
        0 /* field_div */ ,
        0 /* field_encode */ ,
        0 /* field_decode */ ,
        0,                      /* field_set_to_one */
        VR_ec_key_simple_priv2oct,
        VR_ec_key_simple_oct2priv,
        0, /* set private */
        VR_ec_key_simple_generate_key,
        VR_ec_key_simple_check_key,
        VR_ec_key_simple_generate_public_key,
        0, /* keycopy */
        0, /* keyfinish */
        VR_ecdh_simple_compute_key,
        0, /* field_inverse_mod_ord */
        VR_ec_GFp_simple_blind_coordinates,
        VR_ec_GFp_simple_ladder_pre,
        VR_ec_GFp_simple_ladder_step,
        VR_ec_GFp_simple_ladder_post
    };

    return &ret;
}

int VR_ec_GFp_nist_group_copy(EC_GROUP *dest, const EC_GROUP *src)
{
    dest->field_mod_func = src->field_mod_func;

    return VR_ec_GFp_simple_group_copy(dest, src);
}

int VR_ec_GFp_nist_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX *new_ctx = NULL;

    if (ctx == NULL)
        if ((ctx = new_ctx = VR_BN_CTX_new()) == NULL)
            return 0;

    VR_BN_CTX_start(ctx);

    if (VR_BN_ucmp(VR_BN_get0_nist_prime_192(), p) == 0)
        group->field_mod_func = VR_BN_nist_mod_192;
    else if (VR_BN_ucmp(VR_BN_get0_nist_prime_224(), p) == 0)
        group->field_mod_func = VR_BN_nist_mod_224;
    else if (VR_BN_ucmp(VR_BN_get0_nist_prime_256(), p) == 0)
        group->field_mod_func = VR_BN_nist_mod_256;
    else if (VR_BN_ucmp(VR_BN_get0_nist_prime_384(), p) == 0)
        group->field_mod_func = VR_BN_nist_mod_384;
    else if (VR_BN_ucmp(VR_BN_get0_nist_prime_521(), p) == 0)
        group->field_mod_func = VR_BN_nist_mod_521;
    else {
        ECerr(EC_F_EC_GFP_NIST_GROUP_SET_CURVE, EC_R_NOT_A_NIST_PRIME);
        goto err;
    }

    ret = VR_ec_GFp_simple_group_set_curve(group, p, a, b, ctx);

 err:
    VR_BN_CTX_end(ctx);
    VR_BN_CTX_free(new_ctx);
    return ret;
}

int VR_ec_GFp_nist_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *b, BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX *ctx_new = NULL;

    if (!group || !r || !a || !b) {
        ECerr(EC_F_EC_GFP_NIST_FIELD_MUL, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }
    if (!ctx)
        if ((ctx_new = ctx = VR_BN_CTX_new()) == NULL)
            goto err;

    if (!VR_BN_mul(r, a, b, ctx))
        goto err;
    if (!group->field_mod_func(r, r, group->field, ctx))
        goto err;

    ret = 1;
 err:
    VR_BN_CTX_free(ctx_new);
    return ret;
}

int VR_ec_GFp_nist_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
                          BN_CTX *ctx)
{
    int ret = 0;
    BN_CTX *ctx_new = NULL;

    if (!group || !r || !a) {
        ECerr(EC_F_EC_GFP_NIST_FIELD_SQR, EC_R_PASSED_NULL_PARAMETER);
        goto err;
    }
    if (!ctx)
        if ((ctx_new = ctx = VR_BN_CTX_new()) == NULL)
            goto err;

    if (!VR_BN_sqr(r, a, ctx))
        goto err;
    if (!group->field_mod_func(r, r, group->field, ctx))
        goto err;

    ret = 1;
 err:
    VR_BN_CTX_free(ctx_new);
    return ret;
}
