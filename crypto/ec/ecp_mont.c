/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>

#include "ec_lcl.h"

const EC_METHOD *VR_EC_GFp_mont_method(void)
{
    static const EC_METHOD ret = {
        EC_FLAGS_DEFAULT_OCT,
        NID_X9_62_prime_field,
        VR_ec_GFp_mont_group_init,
        VR_ec_GFp_mont_group_finish,
        VR_ec_GFp_mont_group_clear_finish,
        VR_ec_GFp_mont_group_copy,
        VR_ec_GFp_mont_group_set_curve,
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
        VR_ec_GFp_mont_field_mul,
        VR_ec_GFp_mont_field_sqr,
        0 /* field_div */ ,
        VR_ec_GFp_mont_field_encode,
        VR_ec_GFp_mont_field_decode,
        VR_ec_GFp_mont_field_set_to_one,
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

int VR_ec_GFp_mont_group_init(EC_GROUP *group)
{
    int ok;

    ok = VR_ec_GFp_simple_group_init(group);
    group->field_data1 = NULL;
    group->field_data2 = NULL;
    return ok;
}

void VR_ec_GFp_mont_group_finish(EC_GROUP *group)
{
    VR_BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    VR_BN_free(group->field_data2);
    group->field_data2 = NULL;
    VR_ec_GFp_simple_group_finish(group);
}

void VR_ec_GFp_mont_group_clear_finish(EC_GROUP *group)
{
    VR_BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    VR_BN_clear_free(group->field_data2);
    group->field_data2 = NULL;
    VR_ec_GFp_simple_group_clear_finish(group);
}

int VR_ec_GFp_mont_group_copy(EC_GROUP *dest, const EC_GROUP *src)
{
    VR_BN_MONT_CTX_free(dest->field_data1);
    dest->field_data1 = NULL;
    VR_BN_clear_free(dest->field_data2);
    dest->field_data2 = NULL;

    if (!VR_ec_GFp_simple_group_copy(dest, src))
        return 0;

    if (src->field_data1 != NULL) {
        dest->field_data1 = VR_BN_MONT_CTX_new();
        if (dest->field_data1 == NULL)
            return 0;
        if (!VR_BN_MONT_CTX_copy(dest->field_data1, src->field_data1))
            goto err;
    }
    if (src->field_data2 != NULL) {
        dest->field_data2 = VR_BN_dup(src->field_data2);
        if (dest->field_data2 == NULL)
            goto err;
    }

    return 1;

 err:
    VR_BN_MONT_CTX_free(dest->field_data1);
    dest->field_data1 = NULL;
    return 0;
}

int VR_ec_GFp_mont_group_set_curve(EC_GROUP *group, const BIGNUM *p,
                                const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *one = NULL;
    int ret = 0;

    VR_BN_MONT_CTX_free(group->field_data1);
    group->field_data1 = NULL;
    VR_BN_free(group->field_data2);
    group->field_data2 = NULL;

    if (ctx == NULL) {
        ctx = new_ctx = VR_BN_CTX_new();
        if (ctx == NULL)
            return 0;
    }

    mont = VR_BN_MONT_CTX_new();
    if (mont == NULL)
        goto err;
    if (!VR_BN_MONT_CTX_set(mont, p, ctx)) {
        ECerr(EC_F_EC_GFP_MONT_GROUP_SET_CURVE, ERR_R_BN_LIB);
        goto err;
    }
    one = VR_BN_new();
    if (one == NULL)
        goto err;
    if (!VR_BN_to_montgomery(one, VR_BN_value_one(), mont, ctx))
        goto err;

    group->field_data1 = mont;
    mont = NULL;
    group->field_data2 = one;
    one = NULL;

    ret = VR_ec_GFp_simple_group_set_curve(group, p, a, b, ctx);

    if (!ret) {
        VR_BN_MONT_CTX_free(group->field_data1);
        group->field_data1 = NULL;
        VR_BN_free(group->field_data2);
        group->field_data2 = NULL;
    }

 err:
    VR_BN_free(one);
    VR_BN_CTX_free(new_ctx);
    VR_BN_MONT_CTX_free(mont);
    return ret;
}

int VR_ec_GFp_mont_field_mul(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *b, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_MUL, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return VR_BN_mod_mul_montgomery(r, a, b, group->field_data1, ctx);
}

int VR_ec_GFp_mont_field_sqr(const EC_GROUP *group, BIGNUM *r, const BIGNUM *a,
                          BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_SQR, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return VR_BN_mod_mul_montgomery(r, a, a, group->field_data1, ctx);
}

int VR_ec_GFp_mont_field_encode(const EC_GROUP *group, BIGNUM *r,
                             const BIGNUM *a, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_ENCODE, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return VR_BN_to_montgomery(r, a, (BN_MONT_CTX *)group->field_data1, ctx);
}

int VR_ec_GFp_mont_field_decode(const EC_GROUP *group, BIGNUM *r,
                             const BIGNUM *a, BN_CTX *ctx)
{
    if (group->field_data1 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_DECODE, EC_R_NOT_INITIALIZED);
        return 0;
    }

    return VR_BN_from_montgomery(r, a, group->field_data1, ctx);
}

int VR_ec_GFp_mont_field_set_to_one(const EC_GROUP *group, BIGNUM *r,
                                 BN_CTX *ctx)
{
    if (group->field_data2 == NULL) {
        ECerr(EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE, EC_R_NOT_INITIALIZED);
        return 0;
    }

    if (!VR_BN_copy(r, group->field_data2))
        return 0;
    return 1;
}
