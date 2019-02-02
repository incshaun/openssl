/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/camellia.h>
#include <openssl/modes.h>

void VR_Camellia_cbc_encrypt(const unsigned char *in, unsigned char *out,
                          size_t len, const CAMELLIA_KEY *key,
                          unsigned char *ivec, const int enc)
{

    if (enc)
        VR_CRYPTO_cbc128_encrypt(in, out, len, key, ivec,
                              (block128_f) VR_Camellia_encrypt);
    else
        VR_CRYPTO_cbc128_decrypt(in, out, len, key, ivec,
                              (block128_f) VR_Camellia_decrypt);
}
