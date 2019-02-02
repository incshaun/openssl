/*
 * Copyright 2001-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/opensslv.h>

#include "ec_lcl.h"

/* functions for EC_GROUP objects */

EC_GROUP *VR_EC_GROUP_new(const EC_METHOD *meth)
{
    EC_GROUP *ret;

    if (meth == NULL) {
        ECerr(EC_F_EC_GROUP_NEW, EC_R_SLOT_FULL);
        return NULL;
    }
    if (meth->group_init == 0) {
        ECerr(EC_F_EC_GROUP_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return NULL;
    }

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ECerr(EC_F_EC_GROUP_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->meth = meth;
    if ((ret->meth->flags & EC_FLAGS_CUSTOM_CURVE) == 0) {
        ret->order = VR_BN_new();
        if (ret->order == NULL)
            goto err;
        ret->cofactor = VR_BN_new();
        if (ret->cofactor == NULL)
            goto err;
    }
    ret->asn1_flag = OPENSSL_EC_NAMED_CURVE;
    ret->asn1_form = POINT_CONVERSION_UNCOMPRESSED;
    if (!meth->group_init(ret))
        goto err;
    return ret;

 err:
    VR_BN_free(ret->order);
    VR_BN_free(ret->cofactor);
    OPENVR_SSL_free(ret);
    return NULL;
}

void VR_EC_pre_comp_free(EC_GROUP *group)
{
    switch (group->pre_comp_type) {
    case PCT_none:
        break;
    case PCT_nistz256:
#ifdef ECP_NISTZ256_ASM
        VR_EC_nistz256_pre_comp_free(group->pre_comp.nistz256);
#endif
        break;
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    case PCT_nistp224:
        EC_nistp224_pre_comp_free(group->pre_comp.nistp224);
        break;
    case PCT_nistp256:
        EC_nistp256_pre_comp_free(group->pre_comp.nistp256);
        break;
    case PCT_nistp521:
        EC_nistp521_pre_comp_free(group->pre_comp.nistp521);
        break;
#else
    case PCT_nistp224:
    case PCT_nistp256:
    case PCT_nistp521:
        break;
#endif
    case PCT_ec:
        VR_EC_ec_pre_comp_free(group->pre_comp.ec);
        break;
    }
    group->pre_comp.ec = NULL;
}

void VR_EC_GROUP_free(EC_GROUP *group)
{
    if (!group)
        return;

    if (group->meth->group_finish != 0)
        group->meth->group_finish(group);

    VR_EC_pre_comp_free(group);
    VR_BN_MONT_CTX_free(group->mont_data);
    VR_EC_POINT_free(group->generator);
    VR_BN_free(group->order);
    VR_BN_free(group->cofactor);
    OPENVR_SSL_free(group->seed);
    OPENVR_SSL_free(group);
}

void VR_EC_GROUP_clear_free(EC_GROUP *group)
{
    if (!group)
        return;

    if (group->meth->group_clear_finish != 0)
        group->meth->group_clear_finish(group);
    else if (group->meth->group_finish != 0)
        group->meth->group_finish(group);

    VR_EC_pre_comp_free(group);
    VR_BN_MONT_CTX_free(group->mont_data);
    VR_EC_POINT_clear_free(group->generator);
    VR_BN_clear_free(group->order);
    VR_BN_clear_free(group->cofactor);
    OPENVR_SSL_clear_free(group->seed, group->seed_len);
    OPENVR_SSL_clear_free(group, sizeof(*group));
}

int VR_EC_GROUP_copy(EC_GROUP *dest, const EC_GROUP *src)
{
    if (dest->meth->group_copy == 0) {
        ECerr(EC_F_EC_GROUP_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (dest->meth != src->meth) {
        ECerr(EC_F_EC_GROUP_COPY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (dest == src)
        return 1;

    dest->curve_name = src->curve_name;

    /* Copy precomputed */
    dest->pre_comp_type = src->pre_comp_type;
    switch (src->pre_comp_type) {
    case PCT_none:
        dest->pre_comp.ec = NULL;
        break;
    case PCT_nistz256:
#ifdef ECP_NISTZ256_ASM
        dest->pre_comp.nistz256 = VR_EC_nistz256_pre_comp_dup(src->pre_comp.nistz256);
#endif
        break;
#ifndef OPENSSL_NO_EC_NISTP_64_GCC_128
    case PCT_nistp224:
        dest->pre_comp.nistp224 = EC_nistp224_pre_comp_dup(src->pre_comp.nistp224);
        break;
    case PCT_nistp256:
        dest->pre_comp.nistp256 = EC_nistp256_pre_comp_dup(src->pre_comp.nistp256);
        break;
    case PCT_nistp521:
        dest->pre_comp.nistp521 = EC_nistp521_pre_comp_dup(src->pre_comp.nistp521);
        break;
#else
    case PCT_nistp224:
    case PCT_nistp256:
    case PCT_nistp521:
        break;
#endif
    case PCT_ec:
        dest->pre_comp.ec = VR_EC_ec_pre_comp_dup(src->pre_comp.ec);
        break;
    }

    if (src->mont_data != NULL) {
        if (dest->mont_data == NULL) {
            dest->mont_data = VR_BN_MONT_CTX_new();
            if (dest->mont_data == NULL)
                return 0;
        }
        if (!VR_BN_MONT_CTX_copy(dest->mont_data, src->mont_data))
            return 0;
    } else {
        /* src->generator == NULL */
        VR_BN_MONT_CTX_free(dest->mont_data);
        dest->mont_data = NULL;
    }

    if (src->generator != NULL) {
        if (dest->generator == NULL) {
            dest->generator = VR_EC_POINT_new(dest);
            if (dest->generator == NULL)
                return 0;
        }
        if (!VR_EC_POINT_copy(dest->generator, src->generator))
            return 0;
    } else {
        /* src->generator == NULL */
        VR_EC_POINT_clear_free(dest->generator);
        dest->generator = NULL;
    }

    if ((src->meth->flags & EC_FLAGS_CUSTOM_CURVE) == 0) {
        if (!VR_BN_copy(dest->order, src->order))
            return 0;
        if (!VR_BN_copy(dest->cofactor, src->cofactor))
            return 0;
    }

    dest->asn1_flag = src->asn1_flag;
    dest->asn1_form = src->asn1_form;

    if (src->seed) {
        OPENVR_SSL_free(dest->seed);
        if ((dest->seed = OPENSSL_malloc(src->seed_len)) == NULL) {
            ECerr(EC_F_EC_GROUP_COPY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        if (!memcpy(dest->seed, src->seed, src->seed_len))
            return 0;
        dest->seed_len = src->seed_len;
    } else {
        OPENVR_SSL_free(dest->seed);
        dest->seed = NULL;
        dest->seed_len = 0;
    }

    return dest->meth->group_copy(dest, src);
}

EC_GROUP *VR_EC_GROUP_dup(const EC_GROUP *a)
{
    EC_GROUP *t = NULL;
    int ok = 0;

    if (a == NULL)
        return NULL;

    if ((t = VR_EC_GROUP_new(a->meth)) == NULL)
        return NULL;
    if (!VR_EC_GROUP_copy(t, a))
        goto err;

    ok = 1;

 err:
    if (!ok) {
        VR_EC_GROUP_free(t);
        return NULL;
    }
        return t;
}

const EC_METHOD *VR_EC_GROUP_method_of(const EC_GROUP *group)
{
    return group->meth;
}

int VR_EC_METHOD_get_field_type(const EC_METHOD *meth)
{
    return meth->field_type;
}

static int ec_precompute_mont_data(EC_GROUP *);

int VR_EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator,
                           const BIGNUM *order, const BIGNUM *cofactor)
{
    if (generator == NULL) {
        ECerr(EC_F_EC_GROUP_SET_GENERATOR, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (group->generator == NULL) {
        group->generator = VR_EC_POINT_new(group);
        if (group->generator == NULL)
            return 0;
    }
    if (!VR_EC_POINT_copy(group->generator, generator))
        return 0;

    if (order != NULL) {
        if (!VR_BN_copy(group->order, order))
            return 0;
    } else
        BN_zero(group->order);

    if (cofactor != NULL) {
        if (!VR_BN_copy(group->cofactor, cofactor))
            return 0;
    } else
        BN_zero(group->cofactor);

    /*
     * Some groups have an order with
     * factors of two, which makes the Montgomery setup fail.
     * |group->mont_data| will be NULL in this case.
     */
    if (VR_BN_is_odd(group->order)) {
        return ec_precompute_mont_data(group);
    }

    VR_BN_MONT_CTX_free(group->mont_data);
    group->mont_data = NULL;
    return 1;
}

const EC_POINT *VR_EC_GROUP_get0_generator(const EC_GROUP *group)
{
    return group->generator;
}

BN_MONT_CTX *VR_EC_GROUP_get_mont_data(const EC_GROUP *group)
{
    return group->mont_data;
}

int VR_EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx)
{
    if (group->order == NULL)
        return 0;
    if (!VR_BN_copy(order, group->order))
        return 0;

    return !VR_BN_is_zero(order);
}

const BIGNUM *VR_EC_GROUP_get0_order(const EC_GROUP *group)
{
    return group->order;
}

int VR_EC_GROUP_order_bits(const EC_GROUP *group)
{
    return group->meth->group_order_bits(group);
}

int VR_EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor,
                          BN_CTX *ctx)
{

    if (group->cofactor == NULL)
        return 0;
    if (!VR_BN_copy(cofactor, group->cofactor))
        return 0;

    return !VR_BN_is_zero(group->cofactor);
}

const BIGNUM *VR_EC_GROUP_get0_cofactor(const EC_GROUP *group)
{
    return group->cofactor;
}

void VR_EC_GROUP_set_curve_name(EC_GROUP *group, int nid)
{
    group->curve_name = nid;
}

int VR_EC_GROUP_get_curve_name(const EC_GROUP *group)
{
    return group->curve_name;
}

void VR_EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag)
{
    group->asn1_flag = flag;
}

int VR_EC_GROUP_get_asn1_flag(const EC_GROUP *group)
{
    return group->asn1_flag;
}

void VR_EC_GROUP_set_point_conversion_form(EC_GROUP *group,
                                        point_conversion_form_t form)
{
    group->asn1_form = form;
}

point_conversion_form_t VR_EC_GROUP_get_point_conversion_form(const EC_GROUP
                                                           *group)
{
    return group->asn1_form;
}

size_t VR_EC_GROUP_set_seed(EC_GROUP *group, const unsigned char *p, size_t len)
{
    OPENVR_SSL_free(group->seed);
    group->seed = NULL;
    group->seed_len = 0;

    if (!len || !p)
        return 1;

    if ((group->seed = OPENSSL_malloc(len)) == NULL) {
        ECerr(EC_F_EC_GROUP_SET_SEED, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    memcpy(group->seed, p, len);
    group->seed_len = len;

    return len;
}

unsigned char *VR_EC_GROUP_get0_seed(const EC_GROUP *group)
{
    return group->seed;
}

size_t VR_EC_GROUP_get_seed_len(const EC_GROUP *group)
{
    return group->seed_len;
}

int VR_EC_GROUP_set_curve(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                       const BIGNUM *b, BN_CTX *ctx)
{
    if (group->meth->group_set_curve == 0) {
        ECerr(EC_F_EC_GROUP_SET_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_set_curve(group, p, a, b, ctx);
}

int VR_EC_GROUP_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b,
                       BN_CTX *ctx)
{
    if (group->meth->group_get_curve == NULL) {
        ECerr(EC_F_EC_GROUP_GET_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_get_curve(group, p, a, b, ctx);
}

#if !OPENSSL_API_3
int VR_EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                           const BIGNUM *b, BN_CTX *ctx)
{
    return VR_EC_GROUP_set_curve(group, p, a, b, ctx);
}

int VR_EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
                           BIGNUM *b, BN_CTX *ctx)
{
    return VR_EC_GROUP_get_curve(group, p, a, b, ctx);
}

# ifndef OPENSSL_NO_EC2M
int VR_EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *ctx)
{
    return VR_EC_GROUP_set_curve(group, p, a, b, ctx);
}

int VR_EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
                            BIGNUM *b, BN_CTX *ctx)
{
    return VR_EC_GROUP_get_curve(group, p, a, b, ctx);
}
# endif
#endif

int VR_EC_GROUP_get_degree(const EC_GROUP *group)
{
    if (group->meth->group_get_degree == 0) {
        ECerr(EC_F_EC_GROUP_GET_DEGREE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_get_degree(group);
}

int VR_EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx)
{
    if (group->meth->group_check_discriminant == 0) {
        ECerr(EC_F_EC_GROUP_CHECK_DISCRIMINANT,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    return group->meth->group_check_discriminant(group, ctx);
}

int VR_EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx)
{
    int r = 0;
    BIGNUM *a1, *a2, *a3, *b1, *b2, *b3;
    BN_CTX *ctx_new = NULL;

    /* compare the field types */
    if (VR_EC_METHOD_get_field_type(VR_EC_GROUP_method_of(a)) !=
        VR_EC_METHOD_get_field_type(VR_EC_GROUP_method_of(b)))
        return 1;
    /* compare the curve name (if present in both) */
    if (VR_EC_GROUP_get_curve_name(a) && VR_EC_GROUP_get_curve_name(b) &&
        VR_EC_GROUP_get_curve_name(a) != VR_EC_GROUP_get_curve_name(b))
        return 1;
    if (a->meth->flags & EC_FLAGS_CUSTOM_CURVE)
        return 0;

    if (ctx == NULL)
        ctx_new = ctx = VR_BN_CTX_new();
    if (ctx == NULL)
        return -1;

    VR_BN_CTX_start(ctx);
    a1 = VR_BN_CTX_get(ctx);
    a2 = VR_BN_CTX_get(ctx);
    a3 = VR_BN_CTX_get(ctx);
    b1 = VR_BN_CTX_get(ctx);
    b2 = VR_BN_CTX_get(ctx);
    b3 = VR_BN_CTX_get(ctx);
    if (b3 == NULL) {
        VR_BN_CTX_end(ctx);
        VR_BN_CTX_free(ctx_new);
        return -1;
    }

    /*
     * XXX This approach assumes that the external representation of curves
     * over the same field type is the same.
     */
    if (!a->meth->group_get_curve(a, a1, a2, a3, ctx) ||
        !b->meth->group_get_curve(b, b1, b2, b3, ctx))
        r = 1;

    if (r || VR_BN_cmp(a1, b1) || VR_BN_cmp(a2, b2) || VR_BN_cmp(a3, b3))
        r = 1;

    /* XXX VR_EC_POINT_cmp() assumes that the methods are equal */
    if (r || VR_EC_POINT_cmp(a, VR_EC_GROUP_get0_generator(a),
                          VR_EC_GROUP_get0_generator(b), ctx))
        r = 1;

    if (!r) {
        const BIGNUM *ao, *bo, *ac, *bc;
        /* compare the order and cofactor */
        ao = VR_EC_GROUP_get0_order(a);
        bo = VR_EC_GROUP_get0_order(b);
        ac = VR_EC_GROUP_get0_cofactor(a);
        bc = VR_EC_GROUP_get0_cofactor(b);
        if (ao == NULL || bo == NULL) {
            VR_BN_CTX_end(ctx);
            VR_BN_CTX_free(ctx_new);
            return -1;
        }
        if (VR_BN_cmp(ao, bo) || VR_BN_cmp(ac, bc))
            r = 1;
    }

    VR_BN_CTX_end(ctx);
    VR_BN_CTX_free(ctx_new);

    return r;
}

/* functions for EC_POINT objects */

EC_POINT *VR_EC_POINT_new(const EC_GROUP *group)
{
    EC_POINT *ret;

    if (group == NULL) {
        ECerr(EC_F_EC_POINT_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }
    if (group->meth->point_init == NULL) {
        ECerr(EC_F_EC_POINT_NEW, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return NULL;
    }

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ECerr(EC_F_EC_POINT_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->meth = group->meth;
    ret->curve_name = group->curve_name;

    if (!ret->meth->point_init(ret)) {
        OPENVR_SSL_free(ret);
        return NULL;
    }

    return ret;
}

void VR_EC_POINT_free(EC_POINT *point)
{
    if (!point)
        return;

    if (point->meth->point_finish != 0)
        point->meth->point_finish(point);
    OPENVR_SSL_free(point);
}

void VR_EC_POINT_clear_free(EC_POINT *point)
{
    if (!point)
        return;

    if (point->meth->point_clear_finish != 0)
        point->meth->point_clear_finish(point);
    else if (point->meth->point_finish != 0)
        point->meth->point_finish(point);
    OPENVR_SSL_clear_free(point, sizeof(*point));
}

int VR_EC_POINT_copy(EC_POINT *dest, const EC_POINT *src)
{
    if (dest->meth->point_copy == 0) {
        ECerr(EC_F_EC_POINT_COPY, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (dest->meth != src->meth
            || (dest->curve_name != src->curve_name
                && dest->curve_name != 0
                && src->curve_name != 0)) {
        ECerr(EC_F_EC_POINT_COPY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (dest == src)
        return 1;
    return dest->meth->point_copy(dest, src);
}

EC_POINT *VR_EC_POINT_dup(const EC_POINT *a, const EC_GROUP *group)
{
    EC_POINT *t;
    int r;

    if (a == NULL)
        return NULL;

    t = VR_EC_POINT_new(group);
    if (t == NULL)
        return NULL;
    r = VR_EC_POINT_copy(t, a);
    if (!r) {
        VR_EC_POINT_free(t);
        return NULL;
    }
    return t;
}

const EC_METHOD *VR_EC_POINT_method_of(const EC_POINT *point)
{
    return point->meth;
}

int VR_EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point)
{
    if (group->meth->point_set_to_infinity == 0) {
        ECerr(EC_F_EC_POINT_SET_TO_INFINITY,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (group->meth != point->meth) {
        ECerr(EC_F_EC_POINT_SET_TO_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_set_to_infinity(group, point);
}

int VR_EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             EC_POINT *point, const BIGNUM *x,
                                             const BIGNUM *y, const BIGNUM *z,
                                             BN_CTX *ctx)
{
    if (group->meth->point_set_Jprojective_coordinates_GFp == 0) {
        ECerr(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_set_Jprojective_coordinates_GFp(group, point, x,
                                                              y, z, ctx);
}

int VR_EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             const EC_POINT *point, BIGNUM *x,
                                             BIGNUM *y, BIGNUM *z,
                                             BN_CTX *ctx)
{
    if (group->meth->point_get_Jprojective_coordinates_GFp == 0) {
        ECerr(EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP,
              EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->point_get_Jprojective_coordinates_GFp(group, point, x,
                                                              y, z, ctx);
}

int VR_EC_POINT_set_affine_coordinates(const EC_GROUP *group, EC_POINT *point,
                                    const BIGNUM *x, const BIGNUM *y,
                                    BN_CTX *ctx)
{
    if (group->meth->point_set_affine_coordinates == NULL) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (!group->meth->point_set_affine_coordinates(group, point, x, y, ctx))
        return 0;

    if (VR_EC_POINT_is_on_curve(group, point, ctx) <= 0) {
        ECerr(EC_F_EC_POINT_SET_AFFINE_COORDINATES, EC_R_POINT_IS_NOT_ON_CURVE);
        return 0;
    }
    return 1;
}

#if !OPENSSL_API_3
int VR_EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group,
                                        EC_POINT *point, const BIGNUM *x,
                                        const BIGNUM *y, BN_CTX *ctx)
{
    return VR_EC_POINT_set_affine_coordinates(group, point, x, y, ctx);
}

# ifndef OPENSSL_NO_EC2M
int VR_EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group,
                                         EC_POINT *point, const BIGNUM *x,
                                         const BIGNUM *y, BN_CTX *ctx)
{
    return VR_EC_POINT_set_affine_coordinates(group, point, x, y, ctx);
}
# endif
#endif

int VR_EC_POINT_get_affine_coordinates(const EC_GROUP *group,
                                    const EC_POINT *point, BIGNUM *x, BIGNUM *y,
                                    BN_CTX *ctx)
{
    if (group->meth->point_get_affine_coordinates == NULL) {
        ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    if (VR_EC_POINT_is_at_infinity(group, point)) {
        ECerr(EC_F_EC_POINT_GET_AFFINE_COORDINATES, EC_R_POINT_AT_INFINITY);
        return 0;
    }
    return group->meth->point_get_affine_coordinates(group, point, x, y, ctx);
}

#if !OPENSSL_API_3
int VR_EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
                                        const EC_POINT *point, BIGNUM *x,
                                        BIGNUM *y, BN_CTX *ctx)
{
    return VR_EC_POINT_get_affine_coordinates(group, point, x, y, ctx);
}

# ifndef OPENSSL_NO_EC2M
int VR_EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group,
                                         const EC_POINT *point, BIGNUM *x,
                                         BIGNUM *y, BN_CTX *ctx)
{
    return VR_EC_POINT_get_affine_coordinates(group, point, x, y, ctx);
}
# endif
#endif

int VR_EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 const EC_POINT *b, BN_CTX *ctx)
{
    if (group->meth->add == 0) {
        ECerr(EC_F_EC_POINT_ADD, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(r, group) || !ec_point_is_compat(a, group)
        || !ec_point_is_compat(b, group)) {
        ECerr(EC_F_EC_POINT_ADD, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->add(group, r, a, b, ctx);
}

int VR_EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a,
                 BN_CTX *ctx)
{
    if (group->meth->dbl == 0) {
        ECerr(EC_F_EC_POINT_DBL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(r, group) || !ec_point_is_compat(a, group)) {
        ECerr(EC_F_EC_POINT_DBL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->dbl(group, r, a, ctx);
}

int VR_EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx)
{
    if (group->meth->invert == 0) {
        ECerr(EC_F_EC_POINT_INVERT, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(a, group)) {
        ECerr(EC_F_EC_POINT_INVERT, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->invert(group, a, ctx);
}

int VR_EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *point)
{
    if (group->meth->is_at_infinity == 0) {
        ECerr(EC_F_EC_POINT_IS_AT_INFINITY,
              ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINT_IS_AT_INFINITY, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->is_at_infinity(group, point);
}

/*
 * Check whether an EC_POINT is on the curve or not. Note that the return
 * value for this function should NOT be treated as a boolean. Return values:
 *  1: The point is on the curve
 *  0: The point is not on the curve
 * -1: An error occurred
 */
int VR_EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point,
                         BN_CTX *ctx)
{
    if (group->meth->is_on_curve == 0) {
        ECerr(EC_F_EC_POINT_IS_ON_CURVE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINT_IS_ON_CURVE, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->is_on_curve(group, point, ctx);
}

int VR_EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b,
                 BN_CTX *ctx)
{
    if (group->meth->point_cmp == 0) {
        ECerr(EC_F_EC_POINT_CMP, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return -1;
    }
    if (!ec_point_is_compat(a, group) || !ec_point_is_compat(b, group)) {
        ECerr(EC_F_EC_POINT_CMP, EC_R_INCOMPATIBLE_OBJECTS);
        return -1;
    }
    return group->meth->point_cmp(group, a, b, ctx);
}

int VR_EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx)
{
    if (group->meth->make_affine == 0) {
        ECerr(EC_F_EC_POINT_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (!ec_point_is_compat(point, group)) {
        ECerr(EC_F_EC_POINT_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    return group->meth->make_affine(group, point, ctx);
}

int VR_EC_POINTs_make_affine(const EC_GROUP *group, size_t num,
                          EC_POINT *points[], BN_CTX *ctx)
{
    size_t i;

    if (group->meth->points_make_affine == 0) {
        ECerr(EC_F_EC_POINTS_MAKE_AFFINE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    for (i = 0; i < num; i++) {
        if (!ec_point_is_compat(points[i], group)) {
            ECerr(EC_F_EC_POINTS_MAKE_AFFINE, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }
    return group->meth->points_make_affine(group, num, points, ctx);
}

/*
 * Functions for point multiplication. If group->meth->mul is 0, we use the
 * wNAF-based implementations in ec_mult.c; otherwise we dispatch through
 * methods.
 */

int VR_EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                  size_t num, const EC_POINT *points[],
                  const BIGNUM *scalars[], BN_CTX *ctx)
{
    int ret = 0;
    size_t i = 0;
    BN_CTX *new_ctx = NULL;

    if ((scalar == NULL) && (num == 0)) {
        return VR_EC_POINT_set_to_infinity(group, r);
    }

    if (!ec_point_is_compat(r, group)) {
        ECerr(EC_F_EC_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }
    for (i = 0; i < num; i++) {
        if (!ec_point_is_compat(points[i], group)) {
            ECerr(EC_F_EC_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }

    if (ctx == NULL && (ctx = new_ctx = VR_BN_CTX_secure_new()) == NULL) {
        ECerr(EC_F_EC_POINTS_MUL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (group->meth->mul != NULL)
        ret = group->meth->mul(group, r, scalar, num, points, scalars, ctx);
    else
        /* use default */
        ret = VR_ec_wNAF_mul(group, r, scalar, num, points, scalars, ctx);

    VR_BN_CTX_free(new_ctx);
    return ret;
}

int VR_EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
                 const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
{
    /* just a convenient interface to VR_EC_POINTs_mul() */

    const EC_POINT *points[1];
    const BIGNUM *scalars[1];

    points[0] = point;
    scalars[0] = p_scalar;

    return VR_EC_POINTs_mul(group, r, g_scalar,
                         (point != NULL
                          && p_scalar != NULL), points, scalars, ctx);
}

int VR_EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    if (group->meth->mul == 0)
        /* use default */
        return VR_ec_wNAF_precompute_mult(group, ctx);

    if (group->meth->precompute_mult != 0)
        return group->meth->precompute_mult(group, ctx);
    else
        return 1;               /* nothing to do, so report success */
}

int VR_EC_GROUP_have_precompute_mult(const EC_GROUP *group)
{
    if (group->meth->mul == 0)
        /* use default */
        return VR_ec_wNAF_have_precompute_mult(group);

    if (group->meth->have_precompute_mult != 0)
        return group->meth->have_precompute_mult(group);
    else
        return 0;               /* cannot tell whether precomputation has
                                 * been performed */
}

/*
 * ec_precompute_mont_data sets |group->mont_data| from |group->order| and
 * returns one on success. On error it returns zero.
 */
static int ec_precompute_mont_data(EC_GROUP *group)
{
    BN_CTX *ctx = VR_BN_CTX_new();
    int ret = 0;

    VR_BN_MONT_CTX_free(group->mont_data);
    group->mont_data = NULL;

    if (ctx == NULL)
        goto err;

    group->mont_data = VR_BN_MONT_CTX_new();
    if (group->mont_data == NULL)
        goto err;

    if (!VR_BN_MONT_CTX_set(group->mont_data, group->order, ctx)) {
        VR_BN_MONT_CTX_free(group->mont_data);
        group->mont_data = NULL;
        goto err;
    }

    ret = 1;

 err:

    VR_BN_CTX_free(ctx);
    return ret;
}

int VR_EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg)
{
    return VR_CRYPTO_set_ex_data(&key->ex_data, idx, arg);
}

void *VR_EC_KEY_get_ex_data(const EC_KEY *key, int idx)
{
    return VR_CRYPTO_get_ex_data(&key->ex_data, idx);
}

int VR_ec_group_simple_order_bits(const EC_GROUP *group)
{
    if (group->order == NULL)
        return 0;
    return VR_BN_num_bits(group->order);
}

static int ec_field_inverse_mod_ord(const EC_GROUP *group, BIGNUM *r,
                                    const BIGNUM *x, BN_CTX *ctx)
{
    BIGNUM *e = NULL;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (group->mont_data == NULL)
        return 0;

    if (ctx == NULL && (ctx = new_ctx = VR_BN_CTX_secure_new()) == NULL)
        return 0;

    VR_BN_CTX_start(ctx);
    if ((e = VR_BN_CTX_get(ctx)) == NULL)
        goto err;

    /*-
     * We want inverse in constant time, therefore we utilize the fact
     * order must be prime and use Fermats Little Theorem instead.
     */
    if (!VR_BN_set_word(e, 2))
        goto err;
    if (!VR_BN_sub(e, group->order, e))
        goto err;
    /*-
     * Exponent e is public.
     * No need for scatter-gather or BN_FLG_CONSTTIME.
     */
    if (!VR_BN_mod_exp_mont(r, x, e, group->order, ctx, group->mont_data))
        goto err;

    ret = 1;

 err:
    if (ctx != NULL)
        VR_BN_CTX_end(ctx);
    VR_BN_CTX_free(new_ctx);
    return ret;
}

/*-
 * Default behavior, if group->meth->field_inverse_mod_ord is NULL:
 * - When group->order is even, this function returns an error.
 * - When group->order is otherwise composite, the correctness
 *   of the output is not guaranteed.
 * - When x is outside the range [1, group->order), the correctness
 *   of the output is not guaranteed.
 * - Otherwise, this function returns the multiplicative inverse in the
 *   range [1, group->order).
 *
 * EC_METHODs must implement their own field_inverse_mod_ord for
 * other functionality.
 */
int VR_ec_group_do_inverse_ord(const EC_GROUP *group, BIGNUM *res,
                            const BIGNUM *x, BN_CTX *ctx)
{
    if (group->meth->field_inverse_mod_ord != NULL)
        return group->meth->field_inverse_mod_ord(group, res, x, ctx);
    else
        return ec_field_inverse_mod_ord(group, res, x, ctx);
}

/*-
 * Coordinate blinding for EC_POINT.
 *
 * The underlying EC_METHOD can optionally implement this function:
 * underlying implementations should return 0 on errors, or 1 on
 * success.
 *
 * This wrapper returns 1 in case the underlying EC_METHOD does not
 * support coordinate blinding.
 */
int VR_ec_point_blind_coordinates(const EC_GROUP *group, EC_POINT *p, BN_CTX *ctx)
{
    if (group->meth->blind_coordinates == NULL)
        return 1; /* ignore if not implemented */

    return group->meth->blind_coordinates(group, p, ctx);
}
