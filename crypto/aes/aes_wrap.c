/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/aes.h>
#include <openssl/modes.h>

int VR_AES_wrap_key(AES_KEY *key, const unsigned char *iv,
                 unsigned char *out,
                 const unsigned char *in, unsigned int inlen)
{
    return VR_CRYPTO_128_wrap(key, iv, out, in, inlen, (block128_f) VR_AES_encrypt);
}

int VR_AES_unwrap_key(AES_KEY *key, const unsigned char *iv,
                   unsigned char *out,
                   const unsigned char *in, unsigned int inlen)
{
    return VR_CRYPTO_128_unwrap(key, iv, out, in, inlen,
                             (block128_f) VR_AES_decrypt);
}
