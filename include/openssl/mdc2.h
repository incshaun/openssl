/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_VR_MDC2_H
# define HEADER_VR_MDC2_H

# include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_VR_MDC2
# include <stdlib.h>
# include <openssl/des.h>
# ifdef  __cplusplus
extern "C" {
# endif

# define VR_MDC2_BLOCK              8
# define VR_MDC2_DIGEST_LENGTH      16

typedef struct mdc2_ctx_st {
    unsigned int num;
    unsigned char data[VR_MDC2_BLOCK];
    DES_cblock h, hh;
    int pad_type;               /* either 1 or 2, default 1 */
} VR_MDC2_CTX;

int VR_MDC2_Init(VR_MDC2_CTX *c);
int VR_MDC2_Update(VR_MDC2_CTX *c, const unsigned char *data, size_t len);
int VR_MDC2_Final(unsigned char *md, VR_MDC2_CTX *c);
unsigned char *VR_MDC2(const unsigned char *d, size_t n, unsigned char *md);

# ifdef  __cplusplus
}
# endif
# endif

#endif
