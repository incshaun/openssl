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

/*
 * The input and output encrypted as though 128bit cfb mode is being used.
 * The extra state information to record how much of the 128bit block we have
 * used is contained in *num;
 */

void VR_Camellia_cfb128_encrypt(const unsigned char *in, unsigned char *out,
                             size_t length, const CAMELLIA_KEY *key,
                             unsigned char *ivec, int *num, const int enc)
{

    VR_CRYPTO_cfb128_encrypt(in, out, length, key, ivec, num, enc,
                          (block128_f) VR_Camellia_encrypt);
}

/* N.B. This expects the input to be packed, MS bit first */
void VR_Camellia_cfb1_encrypt(const unsigned char *in, unsigned char *out,
                           size_t length, const CAMELLIA_KEY *key,
                           unsigned char *ivec, int *num, const int enc)
{
    VR_CRYPTO_cfb128_1_encrypt(in, out, length, key, ivec, num, enc,
                            (block128_f) VR_Camellia_encrypt);
}

void VR_Camellia_cfb8_encrypt(const unsigned char *in, unsigned char *out,
                           size_t length, const CAMELLIA_KEY *key,
                           unsigned char *ivec, int *num, const int enc)
{
    VR_CRYPTO_cfb128_8_encrypt(in, out, length, key, ivec, num, enc,
                            (block128_f) VR_Camellia_encrypt);
}
