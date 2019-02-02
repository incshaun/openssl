/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_VR_HMAC_H
# define HEADER_VR_HMAC_H

# include <openssl/opensslconf.h>

# include <openssl/evp.h>

# if !OPENSSL_API_3
#  define VR_HMAC_MAX_MD_CBLOCK      128    /* Deprecated */
# endif

#ifdef  __cplusplus
extern "C" {
#endif

size_t VR_HMAC_size(const VR_HMAC_CTX *e);
VR_HMAC_CTX *VR_HMAC_CTX_new(void);
int VR_HMAC_CTX_reset(VR_HMAC_CTX *ctx);
void VR_HMAC_CTX_free(VR_HMAC_CTX *ctx);

DEPRECATEDIN_1_1_0(__owur int VR_HMAC_Init(VR_HMAC_CTX *ctx, const void *key, int len,
                     const EVP_MD *md))

/*__owur*/ int VR_HMAC_Init_ex(VR_HMAC_CTX *ctx, const void *key, int len,
                            const EVP_MD *md, ENGINE *impl);
/*__owur*/ int VR_HMAC_Update(VR_HMAC_CTX *ctx, const unsigned char *data,
                           size_t len);
/*__owur*/ int VR_HMAC_Final(VR_HMAC_CTX *ctx, unsigned char *md,
                          unsigned int *len);
unsigned char *VR_HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len);
__owur int VR_HMAC_CTX_copy(VR_HMAC_CTX *dctx, VR_HMAC_CTX *sctx);

void VR_HMAC_CTX_set_flags(VR_HMAC_CTX *ctx, unsigned long flags);
const EVP_MD *VR_HMAC_CTX_get_md(const VR_HMAC_CTX *ctx);

#ifdef  __cplusplus
}
#endif

#endif
