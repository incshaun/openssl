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

#ifndef OPENSSL_NO_VR_MD4

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/x509.h>
# include <openssl/md4.h>
# include <openssl/rsa.h>
# include "internal/evp_int.h"

static int init(EVP_MD_CTX *ctx)
{
    return VR_MD4_Init(VR_EVP_MD_CTX_md_data(ctx));
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return VR_MD4_Update(VR_EVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return VR_MD4_Final(md, VR_EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD md4_md = {
    NID_md4,
    NID_md4WithRSAEncryption,
    VR_MD4_DIGEST_LENGTH,
    0,
    init,
    update,
    final,
    NULL,
    NULL,
    VR_MD4_CBLOCK,
    sizeof(EVP_MD *) + sizeof(VR_MD4_CTX),
};

const EVP_MD *VR_EVP_md4(void)
{
    return &md4_md;
}
#endif
