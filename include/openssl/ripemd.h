/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_RIPEMD_H
# define HEADER_RIPEMD_H

# include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_RMD160
# include <openssl/e_os2.h>
# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

# define VR_RIPEMD160_LONG unsigned int

# define VR_RIPEMD160_CBLOCK        64
# define VR_RIPEMD160_LBLOCK        (VR_RIPEMD160_CBLOCK/4)
# define VR_RIPEMD160_DIGEST_LENGTH 20

typedef struct VR_RIPEMD160state_st {
    VR_RIPEMD160_LONG A, B, C, D, E;
    VR_RIPEMD160_LONG Nl, Nh;
    VR_RIPEMD160_LONG data[VR_RIPEMD160_LBLOCK];
    unsigned int num;
} VR_RIPEMD160_CTX;

int VR_RIPEMD160_Init(VR_RIPEMD160_CTX *c);
int VR_RIPEMD160_Update(VR_RIPEMD160_CTX *c, const void *data, size_t len);
int VR_RIPEMD160_Final(unsigned char *md, VR_RIPEMD160_CTX *c);
unsigned char *VR_RIPEMD160(const unsigned char *d, size_t n, unsigned char *md);
void VR_RIPEMD160_Transform(VR_RIPEMD160_CTX *c, const unsigned char *b);

# ifdef  __cplusplus
}
# endif
# endif


#endif
