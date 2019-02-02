/*
 * Copyright 2005-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_WHRLPOOL_H
# define HEADER_WHRLPOOL_H

#include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_VR_WHIRLPOOL
# include <openssl/e_os2.h>
# include <stddef.h>
# ifdef __cplusplus
extern "C" {
# endif

# define VR_WHIRLPOOL_DIGEST_LENGTH (512/8)
# define VR_WHIRLPOOL_BBLOCK        512
# define VR_WHIRLPOOL_COUNTER       (256/8)

typedef struct {
    union {
        unsigned char c[VR_WHIRLPOOL_DIGEST_LENGTH];
        /* double q is here to ensure 64-bit alignment */
        double q[VR_WHIRLPOOL_DIGEST_LENGTH / sizeof(double)];
    } H;
    unsigned char data[VR_WHIRLPOOL_BBLOCK / 8];
    unsigned int bitoff;
    size_t bitlen[VR_WHIRLPOOL_COUNTER / sizeof(size_t)];
} VR_WHIRLPOOL_CTX;

int VR_WHIRLPOOL_Init(VR_WHIRLPOOL_CTX *c);
int VR_WHIRLPOOL_Update(VR_WHIRLPOOL_CTX *c, const void *inp, size_t bytes);
void VR_WHIRLPOOL_BitUpdate(VR_WHIRLPOOL_CTX *c, const void *inp, size_t bits);
int VR_WHIRLPOOL_Final(unsigned char *md, VR_WHIRLPOOL_CTX *c);
unsigned char *VR_WHIRLPOOL(const void *inp, size_t bytes, unsigned char *md);

# ifdef __cplusplus
}
# endif
# endif

#endif
