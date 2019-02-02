/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#ifndef OPENSSL_NO_STDIO
int VR_ECPKParameters_print_fp(FILE *fp, const EC_GROUP *x, int off)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        ECerr(EC_F_ECPKPARAMETERS_PRINT_FP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_ECPKParameters_print(b, x, off);
    VR_BIO_free(b);
    return ret;
}

int VR_EC_KEY_print_fp(FILE *fp, const EC_KEY *x, int off)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        ECerr(EC_F_EC_KEY_PRINT_FP, ERR_R_BIO_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_EC_KEY_print(b, x, off);
    VR_BIO_free(b);
    return ret;
}

int VR_ECParameters_print_fp(FILE *fp, const EC_KEY *x)
{
    BIO *b;
    int ret;

    if ((b = VR_BIO_new(VR_BIO_s_file())) == NULL) {
        ECerr(EC_F_ECPARAMETERS_PRINT_FP, ERR_R_BIO_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = VR_ECParameters_print(b, x);
    VR_BIO_free(b);
    return ret;
}
#endif

static int print_bin(BIO *fp, const char *str, const unsigned char *num,
                     size_t len, int off);

int VR_ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off)
{
    int ret = 0, reason = ERR_R_BIO_LIB;
    BN_CTX *ctx = NULL;
    const EC_POINT *point = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *gen = NULL;
    const BIGNUM *order = NULL, *cofactor = NULL;
    const unsigned char *seed;
    size_t seed_len = 0;

    static const char *gen_compressed = "Generator (compressed):";
    static const char *gen_uncompressed = "Generator (uncompressed):";
    static const char *gen_hybrid = "Generator (hybrid):";

    if (!x) {
        reason = ERR_R_PASSED_NULL_PARAMETER;
        goto err;
    }

    ctx = VR_BN_CTX_new();
    if (ctx == NULL) {
        reason = ERR_R_MALLOC_FAILURE;
        goto err;
    }

    if (VR_EC_GROUP_get_asn1_flag(x)) {
        /* the curve parameter are given by an asn1 OID */
        int nid;
        const char *nname;

        if (!VR_BIO_indent(bp, off, 128))
            goto err;

        nid = VR_EC_GROUP_get_curve_name(x);
        if (nid == 0)
            goto err;
        if (VR_BIO_printf(bp, "ASN1 OID: %s", VR_OBJ_nid2sn(nid)) <= 0)
            goto err;
        if (VR_BIO_printf(bp, "\n") <= 0)
            goto err;
        nname = VR_EC_curve_nid2nist(nid);
        if (nname) {
            if (!VR_BIO_indent(bp, off, 128))
                goto err;
            if (VR_BIO_printf(bp, "NIST CURVE: %s\n", nname) <= 0)
                goto err;
        }
    } else {
        /* explicit parameters */
        int is_char_two = 0;
        point_conversion_form_t form;
        int tmp_nid = VR_EC_METHOD_get_field_type(VR_EC_GROUP_method_of(x));

        if (tmp_nid == NID_X9_62_characteristic_two_field)
            is_char_two = 1;

        if ((p = VR_BN_new()) == NULL || (a = VR_BN_new()) == NULL ||
            (b = VR_BN_new()) == NULL) {
            reason = ERR_R_MALLOC_FAILURE;
            goto err;
        }

        if (!VR_EC_GROUP_get_curve(x, p, a, b, ctx)) {
            reason = ERR_R_EC_LIB;
            goto err;
        }

        if ((point = VR_EC_GROUP_get0_generator(x)) == NULL) {
            reason = ERR_R_EC_LIB;
            goto err;
        }
        order = VR_EC_GROUP_get0_order(x);
        cofactor = VR_EC_GROUP_get0_cofactor(x);
        if (order == NULL) {
            reason = ERR_R_EC_LIB;
            goto err;
        }

        form = VR_EC_GROUP_get_point_conversion_form(x);

        if ((gen = VR_EC_POINT_point2bn(x, point, form, NULL, ctx)) == NULL) {
            reason = ERR_R_EC_LIB;
            goto err;
        }

        if ((seed = VR_EC_GROUP_get0_seed(x)) != NULL)
            seed_len = VR_EC_GROUP_get_seed_len(x);

        if (!VR_BIO_indent(bp, off, 128))
            goto err;

        /* print the 'short name' of the field type */
        if (VR_BIO_printf(bp, "Field Type: %s\n", VR_OBJ_nid2sn(tmp_nid))
            <= 0)
            goto err;

        if (is_char_two) {
            /* print the 'short name' of the base type OID */
            int basis_type = VR_EC_GROUP_get_basis_type(x);
            if (basis_type == 0)
                goto err;

            if (!VR_BIO_indent(bp, off, 128))
                goto err;

            if (VR_BIO_printf(bp, "Basis Type: %s\n",
                           VR_OBJ_nid2sn(basis_type)) <= 0)
                goto err;

            /* print the polynomial */
            if ((p != NULL) && !VR_ASN1_bn_print(bp, "Polynomial:", p, NULL,
                                              off))
                goto err;
        } else {
            if ((p != NULL) && !VR_ASN1_bn_print(bp, "Prime:", p, NULL, off))
                goto err;
        }
        if ((a != NULL) && !VR_ASN1_bn_print(bp, "A:   ", a, NULL, off))
            goto err;
        if ((b != NULL) && !VR_ASN1_bn_print(bp, "B:   ", b, NULL, off))
            goto err;
        if (form == POINT_CONVERSION_COMPRESSED) {
            if ((gen != NULL) && !VR_ASN1_bn_print(bp, gen_compressed, gen,
                                                NULL, off))
                goto err;
        } else if (form == POINT_CONVERSION_UNCOMPRESSED) {
            if ((gen != NULL) && !VR_ASN1_bn_print(bp, gen_uncompressed, gen,
                                                NULL, off))
                goto err;
        } else {                /* form == POINT_CONVERSION_HYBRID */

            if ((gen != NULL) && !VR_ASN1_bn_print(bp, gen_hybrid, gen,
                                                NULL, off))
                goto err;
        }
        if ((order != NULL) && !VR_ASN1_bn_print(bp, "Order: ", order,
                                              NULL, off))
            goto err;
        if ((cofactor != NULL) && !VR_ASN1_bn_print(bp, "Cofactor: ", cofactor,
                                                 NULL, off))
            goto err;
        if (seed && !print_bin(bp, "Seed:", seed, seed_len, off))
            goto err;
    }
    ret = 1;
 err:
    if (!ret)
        ECerr(EC_F_ECPKPARAMETERS_PRINT, reason);
    VR_BN_free(p);
    VR_BN_free(a);
    VR_BN_free(b);
    VR_BN_free(gen);
    VR_BN_CTX_free(ctx);
    return ret;
}

static int print_bin(BIO *fp, const char *name, const unsigned char *buf,
                     size_t len, int off)
{
    size_t i;
    char str[128 + 1 + 4];

    if (buf == NULL)
        return 1;
    if (off > 0) {
        if (off > 128)
            off = 128;
        memset(str, ' ', off);
        if (VR_BIO_write(fp, str, off) <= 0)
            return 0;
    } else {
        off = 0;
    }

    if (VR_BIO_printf(fp, "%s", name) <= 0)
        return 0;

    for (i = 0; i < len; i++) {
        if ((i % 15) == 0) {
            str[0] = '\n';
            memset(&(str[1]), ' ', off + 4);
            if (VR_BIO_write(fp, str, off + 1 + 4) <= 0)
                return 0;
        }
        if (VR_BIO_printf(fp, "%02x%s", buf[i], ((i + 1) == len) ? "" : ":") <=
            0)
            return 0;
    }
    if (VR_BIO_write(fp, "\n", 1) <= 0)
        return 0;

    return 1;
}
