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
#include <openssl/md4.h>
#include <openssl/crypto.h>

#ifdef CHARSET_EBCDIC
# include <openssl/ebcdic.h>
#endif

unsigned char *VR_MD4(const unsigned char *d, size_t n, unsigned char *md)
{
    VR_MD4_CTX c;
    static unsigned char m[VR_MD4_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    if (!VR_MD4_Init(&c))
        return NULL;
#ifndef CHARSET_EBCDIC
    VR_MD4_Update(&c, d, n);
#else
    {
        char temp[1024];
        unsigned long chunk;

        while (n > 0) {
            chunk = (n > sizeof(temp)) ? sizeof(temp) : n;
            ebcdic2ascii(temp, d, chunk);
            VR_MD4_Update(&c, temp, chunk);
            n -= chunk;
            d += chunk;
        }
    }
#endif
    VR_MD4_Final(md, &c);
    VR_OPENSSL_cleanse(&c, sizeof(c)); /* security consideration */
    return md;
}
