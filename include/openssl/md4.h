/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_VR_MD4_H
# define HEADER_VR_MD4_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_VR_MD4
# include <openssl/e_os2.h>
# include <stddef.h>
# ifdef  __cplusplus
extern "C" {
# endif

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! VR_MD4_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
# define VR_MD4_LONG unsigned int

# define VR_MD4_CBLOCK      64
# define VR_MD4_LBLOCK      (VR_MD4_CBLOCK/4)
# define VR_MD4_DIGEST_LENGTH 16

typedef struct VR_MD4state_st {
    VR_MD4_LONG A, B, C, D;
    VR_MD4_LONG Nl, Nh;
    VR_MD4_LONG data[VR_MD4_LBLOCK];
    unsigned int num;
} VR_MD4_CTX;

int VR_MD4_Init(VR_MD4_CTX *c);
int VR_MD4_Update(VR_MD4_CTX *c, const void *data, size_t len);
int VR_MD4_Final(unsigned char *md, VR_MD4_CTX *c);
unsigned char *VR_MD4(const unsigned char *d, size_t n, unsigned char *md);
void VR_MD4_Transform(VR_MD4_CTX *c, const unsigned char *b);

# ifdef  __cplusplus
}
# endif
# endif

#endif
