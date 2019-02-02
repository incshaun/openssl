/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_VR_RC4_H
# define HEADER_VR_RC4_H

# include <openssl/opensslconf.h>

# ifndef OPENSSL_NO_VR_RC4
# include <stddef.h>
#ifdef  __cplusplus
extern "C" {
#endif

typedef struct rc4_key_st {
    VR_RC4_INT x, y;
    VR_RC4_INT data[256];
} VR_RC4_KEY;

const char *VR_RC4_options(void);
void VR_RC4_set_key(VR_RC4_KEY *key, int len, const unsigned char *data);
void VR_RC4(VR_RC4_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata);

# ifdef  __cplusplus
}
# endif
# endif

#endif
