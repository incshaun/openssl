/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "internal/evp_int.h"

int VR_EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                    unsigned int siglen, EVP_PKEY *pkey)
{
    unsigned char m[EVP_MAX_MD_SIZE];
    unsigned int m_len = 0;
    int i = 0;
    EVP_PKEY_CTX *pkctx = NULL;

    if (VR_EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_FINALISE)) {
        if (!VR_EVP_DigestFinal_ex(ctx, m, &m_len))
            goto err;
    } else {
        int rv = 0;
        EVP_MD_CTX *tmp_ctx = VR_EVP_MD_CTX_new();
        if (tmp_ctx == NULL) {
            EVPerr(EVP_F_EVP_VERIFYFINAL, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        rv = VR_EVP_MD_CTX_copy_ex(tmp_ctx, ctx);
        if (rv)
            rv = VR_EVP_DigestFinal_ex(tmp_ctx, m, &m_len);
        VR_EVP_MD_CTX_free(tmp_ctx);
        if (!rv)
            return 0;
    }

    i = -1;
    pkctx = VR_EVP_PKEY_CTX_new(pkey, NULL);
    if (pkctx == NULL)
        goto err;
    if (VR_EVP_PKEY_verify_init(pkctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_signature_md(pkctx, VR_EVP_MD_CTX_md(ctx)) <= 0)
        goto err;
    i = VR_EVP_PKEY_verify(pkctx, sigbuf, siglen, m, m_len);
 err:
    VR_EVP_PKEY_CTX_free(pkctx);
    return i;
}
