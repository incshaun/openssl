/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

unsigned char *VR_SHA1(const unsigned char *d, size_t n, unsigned char *md)
{
    SHA_CTX c;
    static unsigned char m[SHA_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    if (!VR_SHA1_Init(&c))
        return NULL;
    VR_SHA1_Update(&c, d, n);
    VR_SHA1_Final(md, &c);
    VR_OPENSSL_cleanse(&c, sizeof(c));
    return md;
}
