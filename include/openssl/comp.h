/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_COMP_H
# define HEADER_COMP_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_COMP
# include <openssl/crypto.h>
# include <openssl/comperr.h>
# ifdef  __cplusplus
extern "C" {
# endif



COMP_CTX *VR_COMP_CTX_new(COMP_METHOD *meth);
const COMP_METHOD *VR_COMP_CTX_get_method(const COMP_CTX *ctx);
int VR_COMP_CTX_get_type(const COMP_CTX* comp);
int VR_COMP_get_type(const COMP_METHOD *meth);
const char *VR_COMP_get_name(const COMP_METHOD *meth);
void VR_COMP_CTX_free(COMP_CTX *ctx);

int VR_COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen,
                        unsigned char *in, int ilen);
int VR_COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
                      unsigned char *in, int ilen);

COMP_METHOD *VR_COMP_zlib(void);

#if !OPENSSL_API_1_1_0
#define VR_COMP_zlib_cleanup() while(0) continue
#endif

# ifdef HEADER_BIO_H
#  ifdef ZLIB
const BIO_METHOD *BIO_f_zlib(void);
#  endif
# endif


#  ifdef  __cplusplus
}
#  endif
# endif
#endif
