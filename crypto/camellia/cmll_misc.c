/*
 * Copyright 2006-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslv.h>
#include <openssl/camellia.h>
#include "cmll_locl.h"

int VR_Camellia_set_key(const unsigned char *userKey, const int bits,
                     CAMELLIA_KEY *key)
{
    if (!userKey || !key)
        return -1;
    if (bits != 128 && bits != 192 && bits != 256)
        return -2;
    key->grand_rounds = VR_Camellia_Ekeygen(bits, userKey, key->u.rd_key);
    return 0;
}

void VR_Camellia_encrypt(const unsigned char *in, unsigned char *out,
                      const CAMELLIA_KEY *key)
{
    VR_Camellia_EncryptBlock_Rounds(key->grand_rounds, in, key->u.rd_key, out);
}

void VR_Camellia_decrypt(const unsigned char *in, unsigned char *out,
                      const CAMELLIA_KEY *key)
{
    VR_Camellia_DecryptBlock_Rounds(key->grand_rounds, in, key->u.rd_key, out);
}
