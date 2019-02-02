/*
 * Copyright 2002-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "ec_lcl.h"

BIGNUM *VR_EC_POINT_point2bn(const EC_GROUP *group,
                          const EC_POINT *point,
                          point_conversion_form_t form,
                          BIGNUM *ret, BN_CTX *ctx)
{
    size_t buf_len = 0;
    unsigned char *buf;

    buf_len = VR_EC_POINT_point2buf(group, point, form, &buf, ctx);

    if (buf_len == 0)
        return NULL;

    ret = VR_BN_bin2bn(buf, buf_len, ret);

    VR_OPENSSL_free(buf);

    return ret;
}

EC_POINT *VR_EC_POINT_bn2point(const EC_GROUP *group,
                            const BIGNUM *bn, EC_POINT *point, BN_CTX *ctx)
{
    size_t buf_len = 0;
    unsigned char *buf;
    EC_POINT *ret;

    if ((buf_len = VR_BN_num_bytes(bn)) == 0)
        return NULL;
    if ((buf = OPENSSL_malloc(buf_len)) == NULL) {
        ECerr(EC_F_EC_POINT_BN2POINT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!VR_BN_bn2bin(bn, buf)) {
        VR_OPENSSL_free(buf);
        return NULL;
    }

    if (point == NULL) {
        if ((ret = VR_EC_POINT_new(group)) == NULL) {
            VR_OPENSSL_free(buf);
            return NULL;
        }
    } else
        ret = point;

    if (!VR_EC_POINT_oct2point(group, ret, buf, buf_len, ctx)) {
        if (ret != point)
            VR_EC_POINT_clear_free(ret);
        VR_OPENSSL_free(buf);
        return NULL;
    }

    VR_OPENSSL_free(buf);
    return ret;
}

static const char *HEX_DIGITS = "0123456789ABCDEF";

/* the return value must be freed (using VR_OPENSSL_free()) */
char *VR_EC_POINT_point2hex(const EC_GROUP *group,
                         const EC_POINT *point,
                         point_conversion_form_t form, BN_CTX *ctx)
{
    char *ret, *p;
    size_t buf_len = 0, i;
    unsigned char *buf = NULL, *pbuf;

    buf_len = VR_EC_POINT_point2buf(group, point, form, &buf, ctx);

    if (buf_len == 0)
        return NULL;

    ret = OPENSSL_malloc(buf_len * 2 + 2);
    if (ret == NULL) {
        VR_OPENSSL_free(buf);
        return NULL;
    }
    p = ret;
    pbuf = buf;
    for (i = buf_len; i > 0; i--) {
        int v = (int)*(pbuf++);
        *(p++) = HEX_DIGITS[v >> 4];
        *(p++) = HEX_DIGITS[v & 0x0F];
    }
    *p = '\0';

    VR_OPENSSL_free(buf);

    return ret;
}

EC_POINT *VR_EC_POINT_hex2point(const EC_GROUP *group,
                             const char *buf, EC_POINT *point, BN_CTX *ctx)
{
    EC_POINT *ret = NULL;
    BIGNUM *tmp_bn = NULL;

    if (!VR_BN_hex2bn(&tmp_bn, buf))
        return NULL;

    ret = VR_EC_POINT_bn2point(group, tmp_bn, point, ctx);

    VR_BN_clear_free(tmp_bn);

    return ret;
}
