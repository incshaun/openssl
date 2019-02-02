/*
 * Copyright 2002-2018 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <limits.h>

#include "internal/cryptlib.h"

#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
#include "ec_lcl.h"

int VR_ossl_ecdh_compute_key(unsigned char **psec, size_t *pseclen,
                          const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    if (ecdh->group->meth->ecdh_compute_key == NULL) {
        ECerr(EC_F_OSSL_ECDH_COMPUTE_KEY, EC_R_CURVE_DOES_NOT_SUPPORT_ECDH);
        return 0;
    }

    return ecdh->group->meth->ecdh_compute_key(psec, pseclen, pub_key, ecdh);
}

/*-
 * This implementation is based on the following primitives in the IEEE 1363 standard:
 *  - ECKAS-DH1
 *  - ECSVDP-DH
 */
int VR_ecdh_simple_compute_key(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key, const EC_KEY *ecdh)
{
    BN_CTX *ctx;
    EC_POINT *tmp = NULL;
    BIGNUM *x = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    int ret = 0;
    size_t buflen, len;
    unsigned char *buf = NULL;

    if ((ctx = VR_BN_CTX_new()) == NULL)
        goto err;
    VR_BN_CTX_start(ctx);
    x = VR_BN_CTX_get(ctx);
    if (x == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    priv_key = VR_EC_KEY_get0_private_key(ecdh);
    if (priv_key == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_NO_PRIVATE_VALUE);
        goto err;
    }

    group = VR_EC_KEY_get0_group(ecdh);

    if (VR_EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
        if (!VR_EC_GROUP_get_cofactor(group, x, NULL) ||
            !VR_BN_mul(x, x, priv_key, ctx)) {
            ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        priv_key = x;
    }

    if ((tmp = VR_EC_POINT_new(group)) == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!VR_EC_POINT_mul(group, tmp, NULL, pub_key, priv_key, ctx)) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_POINT_ARITHMETIC_FAILURE);
        goto err;
    }

    if (!VR_EC_POINT_get_affine_coordinates(group, tmp, x, NULL, ctx)) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_POINT_ARITHMETIC_FAILURE);
        goto err;
    }

    buflen = (VR_EC_GROUP_get_degree(group) + 7) / 8;
    len = VR_BN_num_bytes(x);
    if (len > buflen) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((buf = OPENSSL_malloc(buflen)) == NULL) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    memset(buf, 0, buflen - len);
    if (len != (size_t)VR_BN_bn2bin(x, buf + buflen - len)) {
        ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_BN_LIB);
        goto err;
    }

    *pout = buf;
    *poutlen = buflen;
    buf = NULL;

    ret = 1;

 err:
    VR_EC_POINT_free(tmp);
    if (ctx)
        VR_BN_CTX_end(ctx);
    VR_BN_CTX_free(ctx);
    VR_OPENSSL_free(buf);
    return ret;
}
