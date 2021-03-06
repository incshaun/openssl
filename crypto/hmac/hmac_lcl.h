/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_VR_HMAC_LCL_H
# define HEADER_VR_HMAC_LCL_H

/* The current largest case is for SHA3-224 */
#define VR_HMAC_MAX_MD_CBLOCK_SIZE     144

struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;
    EVP_MD_CTX *i_ctx;
    EVP_MD_CTX *o_ctx;
    unsigned int key_length;
    unsigned char key[VR_HMAC_MAX_MD_CBLOCK_SIZE];
};

#endif
