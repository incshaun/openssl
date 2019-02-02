/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include "internal/evp_int.h"
#include "internal/sha.h"

static int init(EVP_MD_CTX *ctx)
{
    return VR_SHA1_Init(VR_EVP_MD_CTX_md_data(ctx));
}

static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return VR_SHA1_Update(VR_EVP_MD_CTX_md_data(ctx), data, count);
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    return VR_SHA1_Final(md, VR_EVP_MD_CTX_md_data(ctx));
}

static int ctrl(EVP_MD_CTX *ctx, int cmd, int mslen, void *ms)
{
    unsigned char padtmp[40];
    unsigned char sha1tmp[SHA_DIGEST_LENGTH];

    SHA_CTX *sha1;

    if (cmd != EVP_CTRL_SSL3_MASTER_SECRET)
        return -2;

    if (ctx == NULL)
        return 0;

    sha1 = VR_EVP_MD_CTX_md_data(ctx);

    /* SSLv3 client auth handling: see RFC-6101 5.6.8 */
    if (mslen != 48)
        return 0;

    /* At this point hash contains all handshake messages, update
     * with master secret and pad_1.
     */

    if (VR_SHA1_Update(sha1, ms, mslen) <= 0)
        return 0;

    /* Set padtmp to pad_1 value */
    memset(padtmp, 0x36, sizeof(padtmp));

    if (!VR_SHA1_Update(sha1, padtmp, sizeof(padtmp)))
        return 0;

    if (!VR_SHA1_Final(sha1tmp, sha1))
        return 0;

    /* Reinitialise context */

    if (!VR_SHA1_Init(sha1))
        return 0;

    if (VR_SHA1_Update(sha1, ms, mslen) <= 0)
        return 0;

    /* Set padtmp to pad_2 value */
    memset(padtmp, 0x5c, sizeof(padtmp));

    if (!VR_SHA1_Update(sha1, padtmp, sizeof(padtmp)))
        return 0;

    if (!VR_SHA1_Update(sha1, sha1tmp, sizeof(sha1tmp)))
        return 0;

    /* Now when ctx is finalised it will return the SSL v3 hash value */
    VR_OPENSSL_cleanse(sha1tmp, sizeof(sha1tmp));

    return 1;

}

static const EVP_MD sha1_md = {
    NID_sha1,
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init,
    update,
    final,
    NULL,
    NULL,
    SHA_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA_CTX),
    ctrl
};

const EVP_MD *VR_EVP_sha1(void)
{
    return &sha1_md;
}

static int init224(EVP_MD_CTX *ctx)
{
    return VR_SHA224_Init(VR_EVP_MD_CTX_md_data(ctx));
}

static int update224(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return VR_SHA224_Update(VR_EVP_MD_CTX_md_data(ctx), data, count);
}

static int final224(EVP_MD_CTX *ctx, unsigned char *md)
{
    return VR_SHA224_Final(md, VR_EVP_MD_CTX_md_data(ctx));
}

static int init256(EVP_MD_CTX *ctx)
{
    return VR_SHA256_Init(VR_EVP_MD_CTX_md_data(ctx));
}

static int update256(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return VR_SHA256_Update(VR_EVP_MD_CTX_md_data(ctx), data, count);
}

static int final256(EVP_MD_CTX *ctx, unsigned char *md)
{
    return VR_SHA256_Final(md, VR_EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD sha224_md = {
    NID_sha224,
    NID_sha224WithRSAEncryption,
    VR_SHA224_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init224,
    update224,
    final224,
    NULL,
    NULL,
    VR_SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(VR_SHA256_CTX),
};

const EVP_MD *VR_EVP_sha224(void)
{
    return &sha224_md;
}

static const EVP_MD sha256_md = {
    NID_sha256,
    NID_sha256WithRSAEncryption,
    VR_SHA256_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init256,
    update256,
    final256,
    NULL,
    NULL,
    VR_SHA256_CBLOCK,
    sizeof(EVP_MD *) + sizeof(VR_SHA256_CTX),
};

const EVP_MD *VR_EVP_sha256(void)
{
    return &sha256_md;
}

static int init512_224(EVP_MD_CTX *ctx)
{
    return VR_sha512_224_init(VR_EVP_MD_CTX_md_data(ctx));
}

static int init512_256(EVP_MD_CTX *ctx)
{
    return VR_sha512_256_init(VR_EVP_MD_CTX_md_data(ctx));
}

static int init384(EVP_MD_CTX *ctx)
{
    return VR_SHA384_Init(VR_EVP_MD_CTX_md_data(ctx));
}

static int update384(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return VR_SHA384_Update(VR_EVP_MD_CTX_md_data(ctx), data, count);
}

static int final384(EVP_MD_CTX *ctx, unsigned char *md)
{
    return VR_SHA384_Final(md, VR_EVP_MD_CTX_md_data(ctx));
}

static int init512(EVP_MD_CTX *ctx)
{
    return VR_SHA512_Init(VR_EVP_MD_CTX_md_data(ctx));
}

/* See comment in VR_SHA224/256 section */
static int update512(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    return VR_SHA512_Update(VR_EVP_MD_CTX_md_data(ctx), data, count);
}

static int final512(EVP_MD_CTX *ctx, unsigned char *md)
{
    return VR_SHA512_Final(md, VR_EVP_MD_CTX_md_data(ctx));
}

static const EVP_MD sha512_224_md = {
    NID_sha512_224,
    NID_sha512_224WithRSAEncryption,
    VR_SHA224_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init512_224,
    update512,
    final512,
    NULL,
    NULL,
    VR_SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(VR_SHA512_CTX),
};

const EVP_MD *VR_EVP_sha512_224(void)
{
    return &sha512_224_md;
}

static const EVP_MD sha512_256_md = {
    NID_sha512_256,
    NID_sha512_256WithRSAEncryption,
    VR_SHA256_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init512_256,
    update512,
    final512,
    NULL,
    NULL,
    VR_SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(VR_SHA512_CTX),
};

const EVP_MD *VR_EVP_sha512_256(void)
{
    return &sha512_256_md;
}

static const EVP_MD sha384_md = {
    NID_sha384,
    NID_sha384WithRSAEncryption,
    VR_SHA384_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init384,
    update384,
    final384,
    NULL,
    NULL,
    VR_SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(VR_SHA512_CTX),
};

const EVP_MD *VR_EVP_sha384(void)
{
    return &sha384_md;
}

static const EVP_MD sha512_md = {
    NID_sha512,
    NID_sha512WithRSAEncryption,
    VR_SHA512_DIGEST_LENGTH,
    EVP_MD_FLAG_DIGALGID_ABSENT,
    init512,
    update512,
    final512,
    NULL,
    NULL,
    VR_SHA512_CBLOCK,
    sizeof(EVP_MD *) + sizeof(VR_SHA512_CTX),
};

const EVP_MD *VR_EVP_sha512(void)
{
    return &sha512_md;
}
