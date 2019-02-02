/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "ec_lcl.h"

/* Key derivation function from X9.63/SECG */
/* Way more than we will ever need */
#define ECDH_KDF_MAX    (1 << 30)

int VR_ecdh_KDF_X9_63(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const unsigned char *sinfo, size_t sinfolen,
                   const EVP_MD *md)
{
    EVP_MD_CTX *mctx = NULL;
    int rv = 0;
    unsigned int i;
    size_t mdlen;
    unsigned char ctr[4];
    if (sinfolen > ECDH_KDF_MAX || outlen > ECDH_KDF_MAX
        || Zlen > ECDH_KDF_MAX)
        return 0;
    mctx = VR_EVP_MD_CTX_new();
    if (mctx == NULL)
        return 0;
    mdlen = VR_EVP_MD_size(md);
    for (i = 1;; i++) {
        unsigned char mtmp[EVP_MAX_MD_SIZE];
        if (!VR_EVP_DigestInit_ex(mctx, md, NULL))
            goto err;
        ctr[3] = i & 0xFF;
        ctr[2] = (i >> 8) & 0xFF;
        ctr[1] = (i >> 16) & 0xFF;
        ctr[0] = (i >> 24) & 0xFF;
        if (!VR_EVP_DigestUpdate(mctx, Z, Zlen))
            goto err;
        if (!VR_EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
            goto err;
        if (!VR_EVP_DigestUpdate(mctx, sinfo, sinfolen))
            goto err;
        if (outlen >= mdlen) {
            if (!VR_EVP_DigestFinal(mctx, out, NULL))
                goto err;
            outlen -= mdlen;
            if (outlen == 0)
                break;
            out += mdlen;
        } else {
            if (!VR_EVP_DigestFinal(mctx, mtmp, NULL))
                goto err;
            memcpy(out, mtmp, outlen);
            VR_OPENSSL_cleanse(mtmp, mdlen);
            break;
        }
    }
    rv = 1;
 err:
    VR_EVP_MD_CTX_free(mctx);
    return rv;
}

/*-
 * The old name for VR_ecdh_KDF_X9_63
 * Retained for ABI compatibility
 */
#if !OPENSSL_API_3
int VR_ECDH_KDF_X9_62(unsigned char *out, size_t outlen,
                   const unsigned char *Z, size_t Zlen,
                   const unsigned char *sinfo, size_t sinfolen,
                   const EVP_MD *md)
{
    return VR_ecdh_KDF_X9_63(out, outlen, Z, Zlen, sinfo, sinfolen, md);
}
#endif
