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
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int VR_EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                 unsigned char **ek, int *ekl, unsigned char *iv,
                 EVP_PKEY **pubk, int npubk)
{
    unsigned char key[EVP_MAX_KEY_LENGTH];
    int i;
    int rv = 0;

    if (type) {
        VR_EVP_CIPHER_CTX_reset(ctx);
        if (!VR_EVP_EncryptInit_ex(ctx, type, NULL, NULL, NULL))
            return 0;
    }
    if ((npubk <= 0) || !pubk)
        return 1;
    if (VR_EVP_CIPHER_CTX_rand_key(ctx, key) <= 0)
        return 0;

    if (VR_EVP_CIPHER_CTX_iv_length(ctx)
            && VR_RAND_bytes(iv, VR_EVP_CIPHER_CTX_iv_length(ctx)) <= 0)
        goto err;

    if (!VR_EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        goto err;

    for (i = 0; i < npubk; i++) {
        ekl[i] =
            VR_EVP_PKEY_encrypt_old(ek[i], key, VR_EVP_CIPHER_CTX_key_length(ctx),
                                 pubk[i]);
        if (ekl[i] <= 0) {
            rv = -1;
            goto err;
        }
    }
    rv = npubk;
err:
    VR_OPENSSL_cleanse(key, sizeof(key));
    return rv;
}

int VR_EVP_SealFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i;
    i = VR_EVP_EncryptFinal_ex(ctx, out, outl);
    if (i)
        i = VR_EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
    return i;
}
